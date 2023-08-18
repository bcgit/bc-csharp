using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    using F = Rfc7748.X448Field;

    /// <summary>
    /// A low-level implementation of the Ed448 and Ed448ph instantiations of the Edwards-Curve Digital Signature
    /// Algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
    /// </summary>
    /// <remarks>
    /// The implementation uses the "signed mult-comb" algorithm (for scalar multiplication by a fixed point) from
    /// <a href="https://ia.cr/2012/309">Mike Hamburg, "Fast and compact elliptic-curve cryptography"</a>. Standard
    /// <a href="https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html">projective coordinates</a> are used
    /// for most point arithmetic.
    /// </remarks>
    public static class Ed448
    {
        // x^2 + y^2 == 1 - 39081 * x^2 * y^2

        public enum Algorithm
        {
            Ed448 = 0,
            Ed448ph = 1,
        }

        public sealed class PublicPoint
        {
            internal readonly uint[] m_data;

            internal PublicPoint(uint[] data)
            {
                m_data = data;
            }
        }

        private const int CoordUints = 14;
        private const int PointBytes = CoordUints * 4 + 1;
        private const int ScalarUints = 14;
        private const int ScalarBytes = ScalarUints * 4 + 1;

        public static readonly int PrehashSize = 64;
        public static readonly int PublicKeySize = PointBytes;
        public static readonly int SecretKeySize = 57;
        public static readonly int SignatureSize = PointBytes + ScalarBytes;

        // "SigEd448"
        private static readonly byte[] Dom4Prefix = { 0x53, 0x69, 0x67, 0x45, 0x64, 0x34, 0x34, 0x38 };

        private static readonly uint[] P = { 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
            0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
            0xFFFFFFFFU };

        private static readonly uint[] B_x = { 0x070CC05EU, 0x026A82BCU, 0x00938E26U, 0x080E18B0U, 0x0511433BU,
            0x0F72AB66U, 0x0412AE1AU, 0x0A3D3A46U, 0x0A6DE324U, 0x00F1767EU, 0x04657047U, 0x036DA9E1U, 0x05A622BFU,
            0x0ED221D1U, 0x066BED0DU, 0x04F1970CU };
        private static readonly uint[] B_y = { 0x0230FA14U, 0x008795BFU, 0x07C8AD98U, 0x0132C4EDU, 0x09C4FDBDU,
            0x01CE67C3U, 0x073AD3FFU, 0x005A0C2DU, 0x07789C1EU, 0x0A398408U, 0x0A73736CU, 0x0C7624BEU, 0x003756C9U,
            0x02488762U, 0x016EB6BCU, 0x0693F467U };

        // 2^225 * B
        private static readonly uint[] B225_x = { 0x06909EE2U, 0x01D7605CU, 0x0995EC8AU, 0x0FC4D970U, 0x0CF2B361U,
            0x02D82E9DU, 0x01225F55U, 0x007F0EF6U, 0x0AEE9C55U, 0x0A240C13U, 0x05627B54U, 0x0D449D1EU, 0x03A44575U,
            0x007164A7U, 0x0BD4BD71U, 0x061A15FDU };
        private static readonly uint[] B225_y = { 0x0D3A9FE4U, 0x030696B9U, 0x07E7E326U, 0x068308C7U, 0x0CE0B8C8U,
            0x03AC222BU, 0x0304DB8EU, 0x083EE319U, 0x05E5DB0BU, 0x0ECA503BU, 0x0B1C6539U, 0x078A8DCEU, 0x02D256BCU,
            0x04A8B05EU, 0x0BD9FD57U, 0x0A1C3CB8U };

        private const int C_d = -39081;

        //private const int WnafWidth = 6;
        private const int WnafWidth225 = 5;
        private const int WnafWidthBase = 7;

        // ScalarMultBase supports varying blocks, teeth, spacing so long as their product is in range [449, 479]
        private const int PrecompBlocks = 5;
        private const int PrecompTeeth = 5;
        private const int PrecompSpacing = 18;
        private const int PrecompRange = PrecompBlocks * PrecompTeeth * PrecompSpacing; // 448 < range < 480
        private const int PrecompPoints = 1 << (PrecompTeeth - 1);
        private const int PrecompMask = PrecompPoints - 1;

        private static readonly object PrecompLock = new object();
        private static PointAffine[] PrecompBaseWnaf = null;
        private static PointAffine[] PrecompBase225Wnaf = null;
        private static uint[] PrecompBaseComb = null;

        private struct PointAffine
        {
            internal uint[] x, y;
        }

        private struct PointProjective
        {
            internal uint[] x, y, z;
        }

        // Temp space to avoid allocations in point formulae.
        private struct PointTemp
        {
            internal uint[] r0, r1, r2, r3, r4, r5, r6, r7;
        }

        private static byte[] CalculateS(byte[] r, byte[] k, byte[] s)
        {
            uint[] t = new uint[ScalarUints * 2];   Scalar448.Decode(r, t);
            uint[] u = new uint[ScalarUints];       Scalar448.Decode(k, u);
            uint[] v = new uint[ScalarUints];       Scalar448.Decode(s, v);

            Nat.MulAddTo(ScalarUints, u, v, t);

            byte[] result = new byte[ScalarBytes * 2];
            Codec.Encode32(t, 0, t.Length, result, 0);
            return Scalar448.Reduce(result);
        }

        private static bool CheckContextVar(byte[] ctx)
        {
            return ctx != null && ctx.Length < 256;
        }

        private static int CheckPoint(ref PointAffine p)
        {
            uint[] t = F.Create();
            uint[] u = F.Create();
            uint[] v = F.Create();

            F.Sqr(p.x, u);
            F.Sqr(p.y, v);
            F.Mul(u, v, t);
            F.Add(u, v, u);
            F.Mul(t, -C_d, t);
            F.SubOne(t);
            F.Add(t, u, t);
            F.Normalize(t);

            return F.IsZero(t);
        }

        private static int CheckPoint(PointProjective p)
        {
            uint[] t = F.Create();
            uint[] u = F.Create();
            uint[] v = F.Create();
            uint[] w = F.Create();

            F.Sqr(p.x, u);
            F.Sqr(p.y, v);
            F.Sqr(p.z, w);
            F.Mul(u, v, t);
            F.Add(u, v, u);
            F.Mul(u, w, u);
            F.Sqr(w, w);
            F.Mul(t, -C_d, t);
            F.Sub(t, w, t);
            F.Add(t, u, t);
            F.Normalize(t);

            return F.IsZero(t);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static bool CheckPointFullVar(ReadOnlySpan<byte> p)
        {
            if ((p[PointBytes - 1] & 0x7F) != 0x00)
                return false;

            uint y13 = Codec.Decode32(p[52..]);

            uint t0 = y13;
            uint t1 = y13 ^ P[13];

            for (int i = CoordUints - 2; i > 0; --i)
            {
                uint yi = Codec.Decode32(p[(i * 4)..]);

                // Reject non-canonical encodings (i.e. >= P)
                if (t1 == 0 && yi > P[i])
                    return false;

                t0 |= yi;
                t1 |= yi ^ P[i];
            }

            uint y0 = Codec.Decode32(p);

            // Reject 0 and 1
            if (t0 == 0 && y0 <= 1U)
                return false;

            // Reject P - 1 and non-canonical encodings (i.e. >= P)
            if (t1 == 0 && y0 >= (P[0] - 1U))
                return false;

            return true;
        }
#else
        private static bool CheckPointFullVar(byte[] p)
        {
            if ((p[PointBytes - 1] & 0x7F) != 0x00)
                return false;

            uint y13 = Codec.Decode32(p, 52);

            uint t0 = y13;
            uint t1 = y13 ^ P[13];

            for (int i = CoordUints - 2; i > 0; --i)
            {
                uint yi = Codec.Decode32(p, i * 4);

                // Reject non-canonical encodings (i.e. >= P)
                if (t1 == 0 && yi > P[i])
                    return false;

                t0 |= yi;
                t1 |= yi ^ P[i];
            }

            uint y0 = Codec.Decode32(p, 0);

            // Reject 0 and 1
            if (t0 == 0 && y0 <= 1U)
                return false;

            // Reject P - 1 and non-canonical encodings (i.e. >= P)
            if (t1 == 0 && y0 >= (P[0] - 1U))
                return false;

            return true;
        }
#endif

        private static bool CheckPointOrderVar(ref PointAffine p)
        {
            Init(out PointProjective r);
            ScalarMultOrderVar(ref p, ref r);
            return NormalizeToNeutralElementVar(ref r);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static bool CheckPointVar(ReadOnlySpan<byte> p)
        {
            if ((p[PointBytes - 1] & 0x7F) != 0x00)
                return false;
            if (Codec.Decode32(p[52..]) < P[13])
                return true;

            int last = p[28] == 0xFF ? 7 : 0;
            for (int i = CoordUints - 2; i >= last; --i)
            {
                if (Codec.Decode32(p[(i * 4)..]) < P[i])
                    return true;
            }
            return false;
        }
#else
        private static bool CheckPointVar(byte[] p)
        {
            if ((p[PointBytes - 1] & 0x7F) != 0x00)
                return false;
            if (Codec.Decode32(p, 52) < P[13])
                return true;

            int last = p[28] == 0xFF ? 7 : 0;
            for (int i = CoordUints - 2; i >= last; --i)
            {
                if (Codec.Decode32(p, i * 4) < P[i])
                    return true;
            }
            return false;
        }
#endif

        private static byte[] Copy(byte[] buf, int off, int len)
        {
            byte[] result = new byte[len];
            Array.Copy(buf, off, result, 0, len);
            return result;
        }

        public static IXof CreatePrehash()
        {
            return CreateXof();
        }

        private static IXof CreateXof()
        {
            return new ShakeDigest(256);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static bool DecodePointVar(ReadOnlySpan<byte> p, bool negate, ref PointAffine r)
#else
        private static bool DecodePointVar(byte[] p, bool negate, ref PointAffine r)
#endif
        {
            int x_0 = (p[PointBytes - 1] & 0x80) >> 7;

            F.Decode(p, r.y);

            uint[] u = F.Create();
            uint[] v = F.Create();

            F.Sqr(r.y, u);
            F.Mul(u, (uint)-C_d, v);
            F.Negate(u, u);
            F.AddOne(u);
            F.AddOne(v);

            if (!F.SqrtRatioVar(u, v, r.x))
                return false;

            F.Normalize(r.x);
            if (x_0 == 1 && F.IsZeroVar(r.x))
                return false;

            if (negate ^ (x_0 != (r.x[0] & 1)))
            {
                F.Negate(r.x, r.x);
                F.Normalize(r.x);
            }

            return true;
        }

        private static void Dom4(IXof d, byte phflag, byte[] ctx)
        {
            Debug.Assert(ctx != null);

            int n = Dom4Prefix.Length;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> t = stackalloc byte[n + 2 + ctx.Length];
            Dom4Prefix.CopyTo(t);
            t[n] = phflag;
            t[n + 1] = (byte)ctx.Length;
            ctx.CopyTo(t.Slice(n + 2));

            d.BlockUpdate(t);
#else
            byte[] t = new byte[n + 2 + ctx.Length];
            Dom4Prefix.CopyTo(t, 0);
            t[n] = phflag;
            t[n + 1] = (byte)ctx.Length;
            ctx.CopyTo(t, n + 2);

            d.BlockUpdate(t, 0, t.Length);
#endif
        }

        private static void EncodePoint(ref PointAffine p, byte[] r, int rOff)
        {
            F.Encode(p.y, r, rOff);
            r[rOff + PointBytes - 1] = (byte)((p.x[0] & 1) << 7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void EncodePoint(ref PointAffine p, Span<byte> r)
        {
            F.Encode(p.y, r);
            r[PointBytes - 1] = (byte)((p.x[0] & 1) << 7);
        }
#endif

        public static void EncodePublicPoint(PublicPoint publicPoint, byte[] pk, int pkOff)
        {
            F.Encode(publicPoint.m_data, F.Size, pk, pkOff);
            pk[pkOff + PointBytes - 1] = (byte)((publicPoint.m_data[0] & 1) << 7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void EncodePublicPoint(PublicPoint publicPoint, Span<byte> pk)
        {
            F.Encode(publicPoint.m_data.AsSpan(F.Size), pk);
            pk[PointBytes - 1] = (byte)((publicPoint.m_data[0] & 1) << 7);
        }
#endif

        private static int EncodeResult(ref PointProjective p, byte[] r, int rOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return EncodeResult(ref p, r.AsSpan(rOff));
#else
            Init(out PointAffine q);
            NormalizeToAffine(ref p, ref q);

            int result = CheckPoint(ref q);

            EncodePoint(ref q, r, rOff);

            return result;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static int EncodeResult(ref PointProjective p, Span<byte> r)
        {
            Init(out PointAffine q);
            NormalizeToAffine(ref p, ref q);

            int result = CheckPoint(ref q);

            EncodePoint(ref q, r);

            return result;
        }
#endif

        private static PublicPoint ExportPoint(ref PointAffine p)
        {
            uint[] data = new uint[F.Size * 2];
            F.Copy(p.x, 0, data, 0);
            F.Copy(p.y, 0, data, F.Size);

            return new PublicPoint(data);
        }

        public static void GeneratePrivateKey(SecureRandom random, byte[] k)
        {
            if (k.Length != SecretKeySize)
                throw new ArgumentException(nameof(k));

            random.NextBytes(k);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void GeneratePrivateKey(SecureRandom random, Span<byte> k)
        {
            if (k.Length != SecretKeySize)
                throw new ArgumentException(nameof(k));

            random.NextBytes(k);
        }
#endif

        public static void GeneratePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            GeneratePublicKey(sk.AsSpan(skOff), pk.AsSpan(pkOff));
#else
            IXof d = CreateXof();
            byte[] h = new byte[ScalarBytes * 2];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.OutputFinal(h, 0, h.Length);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            ScalarMultBaseEncoded(s, pk, pkOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void GeneratePublicKey(ReadOnlySpan<byte> sk, Span<byte> pk)
        {
            IXof d = CreateXof();
            Span<byte> h = stackalloc byte[ScalarBytes * 2];

            d.BlockUpdate(sk[..SecretKeySize]);
            d.OutputFinal(h);

            Span<byte> s = stackalloc byte[ScalarBytes];
            PruneScalar(h, s);

            ScalarMultBaseEncoded(s, pk);
        }
#endif

        public static PublicPoint GeneratePublicKey(byte[] sk, int skOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GeneratePublicKey(sk.AsSpan(skOff));
#else
            IXof d = CreateXof();
            byte[] h = new byte[ScalarBytes * 2];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.OutputFinal(h, 0, h.Length);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            Init(out PointProjective p);
            ScalarMultBase(s, ref p);

            Init(out PointAffine q);
            NormalizeToAffine(ref p, ref q);

            if (0 == CheckPoint(ref q))
                throw new InvalidOperationException();

            return ExportPoint(ref q);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static PublicPoint GeneratePublicKey(ReadOnlySpan<byte> sk)
        {
            IXof d = CreateXof();
            Span<byte> h = stackalloc byte[ScalarBytes * 2];

            d.BlockUpdate(sk[..SecretKeySize]);
            d.OutputFinal(h);

            Span<byte> s = stackalloc byte[ScalarBytes];
            PruneScalar(h, s);

            Init(out PointProjective p);
            ScalarMultBase(s, ref p);

            Init(out PointAffine q);
            NormalizeToAffine(ref p, ref q);

            if (0 == CheckPoint(ref q))
                throw new InvalidOperationException();

            return ExportPoint(ref q);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static uint GetWindow4(ReadOnlySpan<uint> x, int n)
#else
        private static uint GetWindow4(uint[] x, int n)
#endif
        {
            int w = (int)((uint)n >> 3), b = (n & 7) << 2;
            return (x[w] >> b) & 15U;
        }

        private static void ImplSign(IXof d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag,
            byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            Dom4(d, phflag, ctx);
            d.BlockUpdate(h, ScalarBytes, ScalarBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.OutputFinal(h, 0, h.Length);

            byte[] r = Scalar448.Reduce(h);
            byte[] R = new byte[PointBytes];
            ScalarMultBaseEncoded(r, R, 0);

            Dom4(d, phflag, ctx);
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(pk, pkOff, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.OutputFinal(h, 0, h.Length);

            byte[] k = Scalar448.Reduce(h);
            byte[] S = CalculateS(r, k, s);

            Array.Copy(R, 0, sig, sigOff, PointBytes);
            Array.Copy(S, 0, sig, sigOff + PointBytes, ScalarBytes);
        }

        private static void ImplSign(byte[] sk, int skOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen,
            byte[] sig, int sigOff)
        {
            if (!CheckContextVar(ctx))
                throw new ArgumentException("ctx");

            IXof d = CreateXof();
            byte[] h = new byte[ScalarBytes * 2];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.OutputFinal(h, 0, h.Length);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            byte[] pk = new byte[PointBytes];
            ScalarMultBaseEncoded(s, pk, 0);

            ImplSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        private static void ImplSign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
            int mOff, int mLen, byte[] sig, int sigOff)
        {
            if (!CheckContextVar(ctx))
                throw new ArgumentException("ctx");

            IXof d = CreateXof();
            byte[] h = new byte[ScalarBytes * 2];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.OutputFinal(h, 0, h.Length);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            ImplSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        private static bool ImplVerify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
            int mOff, int mLen)
        {
            if (!CheckContextVar(ctx))
                throw new ArgumentException("ctx");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> signature = stackalloc byte[SignatureSize];
            signature.CopyFrom(sig.AsSpan(sigOff, SignatureSize));
            var R = signature[..PointBytes];
            var S = signature[PointBytes..];

            Span<byte> A = stackalloc byte[PublicKeySize];
            A.CopyFrom(pk.AsSpan(pkOff));

            if (!CheckPointVar(R))
                return false;

            Span<uint> nS = stackalloc uint[ScalarUints];
            if (!Scalar448.CheckVar(S, nS))
                return false;

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, true, ref pA))
                return false;

            IXof d = CreateXof();
            Span<byte> h = stackalloc byte[ScalarBytes * 2];

            Dom4(d, phflag, ctx);
            d.BlockUpdate(R);
            d.BlockUpdate(A);
            d.BlockUpdate(m.AsSpan(mOff, mLen));
            d.OutputFinal(h);

            Span<byte> k = stackalloc byte[ScalarBytes];
            Scalar448.Reduce(h, k);

            Span<uint> nA = stackalloc uint[ScalarUints];
            Scalar448.Decode(k, nA);

            Span<uint> v0 = stackalloc uint[8];
            Span<uint> v1 = stackalloc uint[8];
#else
            byte[] R = Copy(sig, sigOff, PointBytes);
            byte[] S = Copy(sig, sigOff + PointBytes, ScalarBytes);
            byte[] A = Copy(pk, pkOff, PublicKeySize);

            if (!CheckPointVar(R))
                return false;

            uint[] nS = new uint[ScalarUints];
            if (!Scalar448.CheckVar(S, nS))
                return false;

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, true, ref pA))
                return false;

            IXof d = CreateXof();
            byte[] h = new byte[ScalarBytes * 2];

            Dom4(d, phflag, ctx);
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(A, 0, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.OutputFinal(h, 0, h.Length);

            byte[] k = Scalar448.Reduce(h);

            uint[] nA = new uint[ScalarUints];
            Scalar448.Decode(k, nA);

            uint[] v0 = new uint[8];
            uint[] v1 = new uint[8];
#endif

            Scalar448.ReduceBasisVar(nA, v0, v1);
            Scalar448.Multiply225Var(nS, v1, nS);

            Init(out PointProjective pZ);
            ScalarMultStraus225Var(nS, v0, ref pA, v1, ref pR, ref pZ);
            return NormalizeToNeutralElementVar(ref pZ);
        }

        private static bool ImplVerify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte phflag,
            byte[] m, int mOff, int mLen)
        {
            if (!CheckContextVar(ctx))
                throw new ArgumentException("ctx");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> signature = stackalloc byte[SignatureSize];
            signature.CopyFrom(sig.AsSpan(sigOff, SignatureSize));
            var R = signature[..PointBytes];
            var S = signature[PointBytes..];

            if (!CheckPointVar(R))
                return false;

            Span<uint> nS = stackalloc uint[ScalarUints];
            if (!Scalar448.CheckVar(S, nS))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            F.Negate(publicPoint.m_data, pA.x);
            F.Copy(publicPoint.m_data.AsSpan(F.Size), pA.y);

            Span<byte> A = stackalloc byte[PublicKeySize];
            EncodePublicPoint(publicPoint, A);

            IXof d = CreateXof();
            Span<byte> h = stackalloc byte[ScalarBytes * 2];

            Dom4(d, phflag, ctx);
            d.BlockUpdate(R);
            d.BlockUpdate(A);
            d.BlockUpdate(m.AsSpan(mOff, mLen));
            d.OutputFinal(h);

            Span<byte> k = stackalloc byte[ScalarBytes];
            Scalar448.Reduce(h, k);

            Span<uint> nA = stackalloc uint[ScalarUints];
            Scalar448.Decode(k, nA);

            Span<uint> v0 = stackalloc uint[8];
            Span<uint> v1 = stackalloc uint[8];
#else
            byte[] R = Copy(sig, sigOff, PointBytes);
            byte[] S = Copy(sig, sigOff + PointBytes, ScalarBytes);

            if (!CheckPointVar(R))
                return false;

            uint[] nS = new uint[ScalarUints];
            if (!Scalar448.CheckVar(S, nS))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            F.Negate(publicPoint.m_data, pA.x);
            F.Copy(publicPoint.m_data, F.Size, pA.y, 0);

            byte[] A = new byte[PublicKeySize];
            EncodePublicPoint(publicPoint, A, 0);

            IXof d = CreateXof();
            byte[] h = new byte[ScalarBytes * 2];

            Dom4(d, phflag, ctx);
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(A, 0, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.OutputFinal(h, 0, h.Length);

            byte[] k = Scalar448.Reduce(h);

            uint[] nA = new uint[ScalarUints];
            Scalar448.Decode(k, nA);

            uint[] v0 = new uint[8];
            uint[] v1 = new uint[8];
#endif

            Scalar448.ReduceBasisVar(nA, v0, v1);
            Scalar448.Multiply225Var(nS, v1, nS);

            Init(out PointProjective pZ);
            ScalarMultStraus225Var(nS, v0, ref pA, v1, ref pR, ref pZ);
            return NormalizeToNeutralElementVar(ref pZ);
        }

        private static void Init(out PointAffine r)
        {
            r.x = F.Create();
            r.y = F.Create();
        }

        private static void Init(out PointProjective r)
        {
            r.x = F.Create();
            r.y = F.Create();
            r.z = F.Create();
        }

        private static void Init(out PointTemp r)
        {
            r.r0 = F.Create();
            r.r1 = F.Create();
            r.r2 = F.Create();
            r.r3 = F.Create();
            r.r4 = F.Create();
            r.r5 = F.Create();
            r.r6 = F.Create();
            r.r7 = F.Create();
        }

        private static void InvertZs(PointProjective[] points)
        {
            int count = points.Length;
            uint[] cs = F.CreateTable(count);

            uint[] u = F.Create();
            F.Copy(points[0].z, 0, u, 0);
            F.Copy(u, 0, cs, 0);

            int i = 0;
            while (++i < count)
            {
                F.Mul(u, points[i].z, u);
                F.Copy(u, 0, cs, i * F.Size);
            }

            F.InvVar(u, u);
            --i;

            uint[] t = F.Create();

            while (i > 0)
            {
                int j = i--;
                F.Copy(cs, i * F.Size, t, 0);
                F.Mul(t, u, t);
                F.Mul(u, points[j].z, u);
                F.Copy(t, 0, points[j].z, 0);
            }

            F.Copy(u, 0, points[0].z, 0);
        }

        private static void NormalizeToAffine(ref PointProjective p, ref PointAffine r)
        {
            F.Inv(p.z, r.y);
            F.Mul(r.y, p.x, r.x);
            F.Mul(r.y, p.y, r.y);
            F.Normalize(r.x);
            F.Normalize(r.y);
        }

        private static bool NormalizeToNeutralElementVar(ref PointProjective p)
        {
            F.Normalize(p.x);
            F.Normalize(p.y);
            F.Normalize(p.z);

            return F.IsZeroVar(p.x) && F.AreEqualVar(p.y, p.z);
        }

        private static void PointAdd(ref PointAffine p, ref PointProjective r, ref PointTemp t)
        {
            uint[] b = t.r1;
            uint[] c = t.r2;
            uint[] d = t.r3;
            uint[] e = t.r4;
            uint[] f = t.r5;
            uint[] g = t.r6;
            uint[] h = t.r7;

            F.Sqr(r.z, b);
            F.Mul(p.x, r.x, c);
            F.Mul(p.y, r.y, d);
            F.Mul(c, d, e);
            F.Mul(e, -C_d, e);
            //F.Apm(b, e, f, g);
            F.Add(b, e, f);
            F.Sub(b, e, g);
            F.Add(p.y, p.x, h);
            F.Add(r.y, r.x, e);
            F.Mul(h, e, h);
            //F.Apm(d, c, b, e);
            F.Add(d, c, b);
            F.Sub(d, c, e);
            F.Carry(b);
            F.Sub(h, b, h);
            F.Mul(h, r.z, h);
            F.Mul(e, r.z, e);
            F.Mul(f, h, r.x);
            F.Mul(e, g, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointAdd(ref PointProjective p, ref PointProjective r, ref PointTemp t)
        {
            uint[] a = t.r0;
            uint[] b = t.r1;
            uint[] c = t.r2;
            uint[] d = t.r3;
            uint[] e = t.r4;
            uint[] f = t.r5;
            uint[] g = t.r6;
            uint[] h = t.r7;

            F.Mul(p.z, r.z, a);
            F.Sqr(a, b);
            F.Mul(p.x, r.x, c);
            F.Mul(p.y, r.y, d);
            F.Mul(c, d, e);
            F.Mul(e, -C_d, e);
            //F.Apm(b, e, f, g);
            F.Add(b, e, f);
            F.Sub(b, e, g);
            F.Add(p.y, p.x, h);
            F.Add(r.y, r.x, e);
            F.Mul(h, e, h);
            //F.Apm(d, c, b, e);
            F.Add(d, c, b);
            F.Sub(d, c, e);
            F.Carry(b);
            F.Sub(h, b, h);
            F.Mul(h, a, h);
            F.Mul(e, a, e);
            F.Mul(f, h, r.x);
            F.Mul(e, g, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointAddVar(bool negate, ref PointAffine p, ref PointProjective r, ref PointTemp t)
        {
            uint[] b = t.r1;
            uint[] c = t.r2;
            uint[] d = t.r3;
            uint[] e = t.r4;
            uint[] f = t.r5;
            uint[] g = t.r6;
            uint[] h = t.r7;

            uint[] nb, ne, nf, ng;
            if (negate)
            {
                nb = e; ne = b; nf = g; ng = f;
                F.Sub(p.y, p.x, h);
            }
            else
            {
                nb = b; ne = e; nf = f; ng = g;
                F.Add(p.y, p.x, h);
            }

            F.Sqr(r.z, b);
            F.Mul(p.x, r.x, c);
            F.Mul(p.y, r.y, d);
            F.Mul(c, d, e);
            F.Mul(e, -C_d, e);
            //F.Apm(b, e, nf, ng);
            F.Add(b, e, nf);
            F.Sub(b, e, ng);
            F.Add(r.y, r.x, e);
            F.Mul(h, e, h);
            //F.Apm(d, c, nb, ne);
            F.Add(d, c, nb);
            F.Sub(d, c, ne);
            F.Carry(nb);
            F.Sub(h, b, h);
            F.Mul(h, r.z, h);
            F.Mul(e, r.z, e);
            F.Mul(f, h, r.x);
            F.Mul(e, g, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointAddVar(bool negate, ref PointProjective p, ref PointProjective r, ref PointTemp t)
        {
            uint[] a = t.r0;
            uint[] b = t.r1;
            uint[] c = t.r2;
            uint[] d = t.r3;
            uint[] e = t.r4;
            uint[] f = t.r5;
            uint[] g = t.r6;
            uint[] h = t.r7;

            uint[] nb, ne, nf, ng;
            if (negate)
            {
                nb = e; ne = b; nf = g; ng = f;
                F.Sub(p.y, p.x, h);
            }
            else
            {
                nb = b; ne = e; nf = f; ng = g;
                F.Add(p.y, p.x, h);
            }

            F.Mul(p.z, r.z, a);
            F.Sqr(a, b);
            F.Mul(p.x, r.x, c);
            F.Mul(p.y, r.y, d);
            F.Mul(c, d, e);
            F.Mul(e, -C_d, e);
            //F.Apm(b, e, nf, ng);
            F.Add(b, e, nf);
            F.Sub(b, e, ng);
            F.Add(r.y, r.x, e);
            F.Mul(h, e, h);
            //F.Apm(d, c, nb, ne);
            F.Add(d, c, nb);
            F.Sub(d, c, ne);
            F.Carry(nb);
            F.Sub(h, b, h);
            F.Mul(h, a, h);
            F.Mul(e, a, e);
            F.Mul(f, h, r.x);
            F.Mul(e, g, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointCopy(ref PointAffine p, ref PointProjective r)
        {
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            F.One(r.z);
        }

        private static void PointCopy(ref PointProjective p, ref PointProjective r)
        {
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            F.Copy(p.z, 0, r.z, 0);
        }

        private static void PointDouble(ref PointProjective r, ref PointTemp t)
        {
            uint[] b = t.r1;
            uint[] c = t.r2;
            uint[] d = t.r3;
            uint[] e = t.r4;
            uint[] h = t.r7;
            uint[] j = t.r0;

            F.Add(r.x, r.y, b);
            F.Sqr(b, b);
            F.Sqr(r.x, c);
            F.Sqr(r.y, d);
            F.Add(c, d, e);
            F.Carry(e);
            F.Sqr(r.z, h);
            F.Add(h, h, h);
            F.Carry(h);
            F.Sub(e, h, j);
            F.Sub(b, e, b);
            F.Sub(c, d, c);
            F.Mul(b, j, r.x);
            F.Mul(e, c, r.y);
            F.Mul(e, j, r.z);
        }

        private static void PointLookup(int block, int index, ref PointAffine p)
        {
            Debug.Assert(0 <= block && block < PrecompBlocks);
            Debug.Assert(0 <= index && index < PrecompPoints);

            int off = block * PrecompPoints * 2 * F.Size;

            for (int i = 0; i < PrecompPoints; ++i)
            {
                int cond = ((i ^ index) - 1) >> 31;
                F.CMov(cond, PrecompBaseComb, off, p.x, 0);     off += F.Size;
                F.CMov(cond, PrecompBaseComb, off, p.y, 0);     off += F.Size;
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void PointLookup(ReadOnlySpan<uint> x, int n, ReadOnlySpan<uint> table, ref PointProjective r)
        {
            // TODO This method is currently hardcoded to 4-bit windows and 8 precomputed points

            uint w = GetWindow4(x, n);

            int sign = (int)(w >> (4 - 1)) ^ 1;
            int abs = ((int)w ^ -sign) & 7;

            Debug.Assert(sign == 0 || sign == 1);
            Debug.Assert(0 <= abs && abs < 8);

            for (int i = 0; i < 8; ++i)
            {
                int cond = ((i ^ abs) - 1) >> 31;
                F.CMov(cond, table, r.x);       table = table[F.Size..];
                F.CMov(cond, table, r.y);       table = table[F.Size..];
                F.CMov(cond, table, r.z);       table = table[F.Size..];
            }

            F.CNegate(sign, r.x);
        }
#else
        private static void PointLookup(uint[] x, int n, uint[] table, ref PointProjective r)
        {
            // TODO This method is currently hardcoded to 4-bit windows and 8 precomputed points

            uint w = GetWindow4(x, n);

            int sign = (int)(w >> (4 - 1)) ^ 1;
            int abs = ((int)w ^ -sign) & 7;

            Debug.Assert(sign == 0 || sign == 1);
            Debug.Assert(0 <= abs && abs < 8);

            for (int i = 0, off = 0; i < 8; ++i)
            {
                int cond = ((i ^ abs) - 1) >> 31;
                F.CMov(cond, table, off, r.x, 0);       off += F.Size;
                F.CMov(cond, table, off, r.y, 0);       off += F.Size;
                F.CMov(cond, table, off, r.z, 0);       off += F.Size;
            }

            F.CNegate(sign, r.x);
        }
#endif

        private static void PointLookup15(uint[] table, ref PointProjective r)
        {
            int off = F.Size * 3 * 7;

            F.Copy(table, off, r.x, 0);     off += F.Size;
            F.Copy(table, off, r.y, 0);     off += F.Size;
            F.Copy(table, off, r.z, 0);
        }

        private static uint[] PointPrecompute(ref PointProjective p, int count, ref PointTemp t)
        {
            Debug.Assert(count > 0);

            Init(out PointProjective q);
            PointCopy(ref p, ref q);

            Init(out PointProjective d);
            PointCopy(ref q, ref d);
            PointDouble(ref d, ref t);

            uint[] table = F.CreateTable(count * 3);
            int off = 0;

            int i = 0;
            for (;;)
            {
                F.Copy(q.x, 0, table, off);     off += F.Size;
                F.Copy(q.y, 0, table, off);     off += F.Size;
                F.Copy(q.z, 0, table, off);     off += F.Size;

                if (++i == count)
                    break;

                PointAdd(ref d, ref q, ref t);
            }

            return table;
        }

        private static void PointPrecompute(ref PointAffine p, PointProjective[] points, int pointsOff, int pointsLen,
            ref PointTemp t)
        {
            Debug.Assert(pointsLen > 0);

            Init(out PointProjective d);
            PointCopy(ref p, ref d);
            PointDouble(ref d, ref t);

            Init(out points[pointsOff]);
            PointCopy(ref p, ref points[pointsOff]);

            for (int i = 1; i < pointsLen; ++i)
            {
                Init(out points[pointsOff + i]);
                PointCopy(ref points[pointsOff + i - 1], ref points[pointsOff + i]);
                PointAdd(ref d, ref points[pointsOff + i], ref t);
            }
        }

        private static void PointSetNeutral(ref PointProjective p)
        {
            F.Zero(p.x);
            F.One(p.y);
            F.One(p.z);
        }

        public static void Precompute()
        {
            lock (PrecompLock)
            {
                if (PrecompBaseComb != null)
                    return;

                Debug.Assert(PrecompRange > 448);
                Debug.Assert(PrecompRange < 480);

                int wnafPoints = 1 << (WnafWidthBase - 2);
                int combPoints = PrecompBlocks * PrecompPoints;
                int totalPoints = wnafPoints * 2 + combPoints;

                PointProjective[] points = new PointProjective[totalPoints];
                Init(out PointTemp t);

                Init(out PointAffine B);
                F.Copy(B_x, 0, B.x, 0);
                F.Copy(B_y, 0, B.y, 0);

                PointPrecompute(ref B, points, 0, wnafPoints, ref t);

                Init(out PointAffine B225);
                F.Copy(B225_x, 0, B225.x, 0);
                F.Copy(B225_y, 0, B225.y, 0);

                PointPrecompute(ref B225, points, wnafPoints, wnafPoints, ref t);

                Init(out PointProjective p);
                PointCopy(ref B, ref p);

                int pointsIndex = wnafPoints * 2;
                PointProjective[] toothPowers = new PointProjective[PrecompTeeth];
                for (int tooth = 0; tooth < PrecompTeeth; ++tooth)
                {
                    Init(out toothPowers[tooth]);
                }

                for (int block = 0; block < PrecompBlocks; ++block)
                {
                    ref PointProjective sum = ref points[pointsIndex++];
                    Init(out sum);

                    for (int tooth = 0; tooth < PrecompTeeth; ++tooth)
                    {
                        if (tooth == 0)
                        {
                            PointCopy(ref p, ref sum);
                        }
                        else
                        {
                            PointAdd(ref p, ref sum, ref t);
                        }

                        PointDouble(ref p, ref t);
                        PointCopy(ref p, ref toothPowers[tooth]);

                        if (block + tooth != PrecompBlocks + PrecompTeeth - 2)
                        {
                            for (int spacing = 1; spacing < PrecompSpacing; ++spacing)
                            {
                                PointDouble(ref p, ref t);
                            }
                        }
                    }

                    F.Negate(sum.x, sum.x);

                    for (int tooth = 0; tooth < (PrecompTeeth - 1); ++tooth)
                    {
                        int size = 1 << tooth;
                        for (int j = 0; j < size; ++j, ++pointsIndex)
                        {
                            Init(out points[pointsIndex]);
                            PointCopy(ref points[pointsIndex - size], ref points[pointsIndex]);
                            PointAdd(ref toothPowers[tooth], ref points[pointsIndex], ref t);
                        }
                    }
                }
                Debug.Assert(pointsIndex == totalPoints);

                InvertZs(points);

                PrecompBaseWnaf = new PointAffine[wnafPoints];
                for (int i = 0; i < wnafPoints; ++i)
                {
                    ref PointProjective q = ref points[i];
                    ref PointAffine r = ref PrecompBaseWnaf[i];
                    Init(out r);

                    F.Mul(q.x, q.z, r.x);       F.Normalize(r.x);
                    F.Mul(q.y, q.z, r.y);       F.Normalize(r.y);
                }

                PrecompBase225Wnaf = new PointAffine[wnafPoints];
                for (int i = 0; i < wnafPoints; ++i)
                {
                    ref PointProjective q = ref points[wnafPoints + i];
                    ref PointAffine r = ref PrecompBase225Wnaf[i];
                    Init(out r);

                    F.Mul(q.x, q.z, r.x);       F.Normalize(r.x);
                    F.Mul(q.y, q.z, r.y);       F.Normalize(r.y);
                }

                PrecompBaseComb = F.CreateTable(combPoints * 2);
                int off = 0;
                for (int i = wnafPoints * 2; i < totalPoints; ++i)
                {
                    ref PointProjective q = ref points[i];

                    F.Mul(q.x, q.z, q.x);       F.Normalize(q.x);
                    F.Mul(q.y, q.z, q.y);       F.Normalize(q.y);

                    F.Copy(q.x, 0, PrecompBaseComb, off);       off += F.Size;
                    F.Copy(q.y, 0, PrecompBaseComb, off);       off += F.Size;
                }
                Debug.Assert(off == PrecompBaseComb.Length);
            }
        }

        private static void PruneScalar(byte[] n, int nOff, byte[] r)
        {
            Array.Copy(n, nOff, r, 0, ScalarBytes - 1);

            r[0] &= 0xFC;
            r[ScalarBytes - 2] |= 0x80;
            r[ScalarBytes - 1]  = 0x00;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void PruneScalar(ReadOnlySpan<byte> n, Span<byte> r)
        {
            n[..(ScalarBytes - 1)].CopyTo(r);

            r[0] &= 0xFC;
            r[ScalarBytes - 2] |= 0x80;
            r[ScalarBytes - 1]  = 0x00;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMult(ReadOnlySpan<byte> k, ref PointProjective p, ref PointProjective r)
#else
        private static void ScalarMult(byte[] k, ref PointProjective p, ref PointProjective r)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> n = stackalloc uint[ScalarUints + 1];
#else
            uint[] n = new uint[ScalarUints + 1];
#endif

            Scalar448.Decode(k, n);
            Scalar448.ToSignedDigits(449, n, n);

            // NOTE: Bit 448 is handled explicitly by an initial addition
            Debug.Assert(n[ScalarUints] == 1U);

            Init(out PointProjective q);
            Init(out PointTemp t);
            uint[] table = PointPrecompute(ref p, 8, ref t);

            // Replace first 4 doublings (2^4 * P) with 1 addition (P + 15 * P)
            PointLookup15(table, ref r);
            PointAdd(ref p, ref r, ref t);

            int w = 111;
            for (;;)
            {
                PointLookup(n, w, table, ref q);
                PointAdd(ref q, ref r, ref t);

                if (--w < 0)
                    break;

                for (int i = 0; i < 4; ++i)
                {
                    PointDouble(ref r, ref t);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMultBase(ReadOnlySpan<byte> k, ref PointProjective r)
#else
        private static void ScalarMultBase(byte[] k, ref PointProjective r)
#endif
        {
            // Equivalent (but much slower)
            //Init(out PointProjective p);
            //F.Copy(B_x, 0, p.x, 0);
            //F.Copy(B_y, 0, p.y, 0);
            //F.One(p.z);
            //ScalarMult(k, ref p, ref r);

            Precompute();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> n = stackalloc uint[ScalarUints + 1];
#else
            uint[] n = new uint[ScalarUints + 1];
#endif

            Scalar448.Decode(k, n);
            Scalar448.ToSignedDigits(PrecompRange, n, n);

            Init(out PointAffine p);
            Init(out PointTemp t);

            PointSetNeutral(ref r);

            int cOff = PrecompSpacing - 1;
            for (;;)
            {
                int tPos = cOff;

                for (int block = 0; block < PrecompBlocks; ++block)
                {
                    uint w = 0;
                    for (int tooth = 0; tooth < PrecompTeeth; ++tooth)
                    {
                        uint tBit = n[tPos >> 5] >> (tPos & 0x1F);
                        w &= ~(1U << tooth);
                        w ^= (tBit << tooth);
                        tPos += PrecompSpacing;
                    }

                    int sign = (int)(w >> (PrecompTeeth - 1)) & 1;
                    int abs = ((int)w ^ -sign) & PrecompMask;

                    Debug.Assert(sign == 0 || sign == 1);
                    Debug.Assert(0 <= abs && abs < PrecompPoints);

                    PointLookup(block, abs, ref p);

                    F.CNegate(sign, p.x);

                    PointAdd(ref p, ref r, ref t);
                }

                if (--cOff < 0)
                    break;

                PointDouble(ref r, ref t);
            }
        }

        private static void ScalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ScalarMultBaseEncoded(k.AsSpan(), r.AsSpan(rOff));
#else
            Init(out PointProjective p);
            ScalarMultBase(k, ref p);
            if (0 == EncodeResult(ref p, r, rOff))
                throw new InvalidOperationException();
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMultBaseEncoded(ReadOnlySpan<byte> k, Span<byte> r)
        {
            Init(out PointProjective p);
            ScalarMultBase(k, ref p);
            if (0 == EncodeResult(ref p, r))
                throw new InvalidOperationException();
        }
#endif

        internal static void ScalarMultBaseXY(byte[] k, int kOff, uint[] x, uint[] y)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ScalarMultBaseXY(k.AsSpan(kOff), x.AsSpan(), y.AsSpan());
#else
            byte[] n = new byte[ScalarBytes];
            PruneScalar(k, kOff, n);

            Init(out PointProjective p);
            ScalarMultBase(n, ref p);

            if (0 == CheckPoint(p))
                throw new InvalidOperationException();

            F.Copy(p.x, 0, x, 0);
            F.Copy(p.y, 0, y, 0);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void ScalarMultBaseXY(ReadOnlySpan<byte> k, Span<uint> x, Span<uint> y)
        {
            Span<byte> n = stackalloc byte[ScalarBytes];
            PruneScalar(k, n);

            Init(out PointProjective p);
            ScalarMultBase(n, ref p);

            if (0 == CheckPoint(p))
                throw new InvalidOperationException();

            F.Copy(p.x, x);
            F.Copy(p.y, y);
        }
#endif

        private static void ScalarMultOrderVar(ref PointAffine p, ref PointProjective r)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<sbyte> ws_p = stackalloc sbyte[447];
#else
            sbyte[] ws_p = new sbyte[447];
#endif
            // NOTE: WnafWidth225 because of the special structure of the order 
            Scalar448.GetOrderWnafVar(WnafWidth225, ws_p);

            int count = 1 << (WnafWidth225 - 2);
            PointProjective[] tp = new PointProjective[count];
            Init(out PointTemp t);
            PointPrecompute(ref p, tp, 0, count, ref t);

            PointSetNeutral(ref r);

            for (int bit = 446;;)
            {
                int wp = ws_p[bit];
                if (wp != 0)
                {
                    int index = (wp >> 1) ^ (wp >> 31);
                    PointAddVar(wp < 0, ref tp[index], ref r, ref t);
                }

                if (--bit < 0)
                    break;

                PointDouble(ref r, ref t);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMultStraus225Var(ReadOnlySpan<uint> nb, ReadOnlySpan<uint> np, ref PointAffine p,
            ReadOnlySpan<uint> nq, ref PointAffine q, ref PointProjective r)
#else
        private static void ScalarMultStraus225Var(uint[] nb, uint[] np, ref PointAffine p, uint[] nq,
            ref PointAffine q, ref PointProjective r)
#endif
        {
            Debug.Assert(nb.Length == ScalarUints);
            Debug.Assert(nb[ScalarUints - 1] >> 30 == 0U);
            Debug.Assert(np.Length == 8);
            Debug.Assert((int)np[7] >> 31 == (int)np[7]);
            Debug.Assert(nq.Length == 8);
            Debug.Assert((int)nq[7] >> 31 == (int)nq[7]);

            Precompute();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<sbyte> ws_b = stackalloc sbyte[450];
            Span<sbyte> ws_p = stackalloc sbyte[225];
            Span<sbyte> ws_q = stackalloc sbyte[225];
#else
            sbyte[] ws_b = new sbyte[450];
            sbyte[] ws_p = new sbyte[225];
            sbyte[] ws_q = new sbyte[225];
#endif

            Wnaf.GetSignedVar(nb, WnafWidthBase, ws_b);
            Wnaf.GetSignedVar(np, WnafWidth225, ws_p);
            Wnaf.GetSignedVar(nq, WnafWidth225, ws_q);

            int count = 1 << (WnafWidth225 - 2);
            PointProjective[] tp = new PointProjective[count];
            PointProjective[] tq = new PointProjective[count];
            Init(out PointTemp t);
            PointPrecompute(ref p, tp, 0, count, ref t);
            PointPrecompute(ref q, tq, 0, count, ref t);

            PointSetNeutral(ref r);

            int bit = 225;
            while (--bit >= 0)
            {
                int wb = ws_b[bit];
                if (wb != 0)
                {
                    int index = (wb >> 1) ^ (wb >> 31);
                    PointAddVar(wb < 0, ref PrecompBaseWnaf[index], ref r, ref t);
                }

                int wb225 = ws_b[225 + bit];
                if (wb225 != 0)
                {
                    int index = (wb225 >> 1) ^ (wb225 >> 31);
                    PointAddVar(wb225 < 0, ref PrecompBase225Wnaf[index], ref r, ref t);
                }

                int wp = ws_p[bit];
                if (wp != 0)
                {
                    int index = (wp >> 1) ^ (wp >> 31);
                    PointAddVar(wp < 0, ref tp[index], ref r, ref t);
                }

                int wq = ws_q[bit];
                if (wq != 0)
                {
                    int index = (wq >> 1) ^ (wq >> 31);
                    PointAddVar(wq < 0, ref tq[index], ref r, ref t);
                }

                PointDouble(ref r, ref t);
            }

            // NOTE: Together with the final PointDouble of the loop, this clears the cofactor of 4
            PointDouble(ref r, ref t);
        }

        public static void Sign(byte[] sk, int skOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            byte phflag = 0x00;

            ImplSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        public static void Sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen,
            byte[] sig, int sigOff)
        {
            byte phflag = 0x00;

            ImplSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff)
        {
            byte phflag = 0x01;

            ImplSign(sk, skOff, ctx, phflag, ph, phOff, PrehashSize, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff,
            byte[] sig, int sigOff)
        {
            byte phflag = 0x01;

            ImplSign(sk, skOff, pk, pkOff, ctx, phflag, ph, phOff, PrehashSize, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] ctx, IXof ph, byte[] sig, int sigOff)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.OutputFinal(m, 0, PrehashSize))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            ImplSign(sk, skOff, ctx, phflag, m, 0, m.Length, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, IXof ph, byte[] sig,
            int sigOff)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.OutputFinal(m, 0, PrehashSize))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            ImplSign(sk, skOff, pk, pkOff, ctx, phflag, m, 0, m.Length, sig, sigOff);
        }

        public static bool ValidatePublicKeyFull(byte[] pk, int pkOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ValidatePublicKeyFull(pk.AsSpan(pkOff));
#else
            byte[] A = Copy(pk, pkOff, PublicKeySize);

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, false, ref pA))
                return false;

            return CheckPointOrderVar(ref pA);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool ValidatePublicKeyFull(ReadOnlySpan<byte> pk)
        {
            Span<byte> A = stackalloc byte[PublicKeySize];
            A.CopyFrom(pk);

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, false, ref pA))
                return false;

            return CheckPointOrderVar(ref pA);
        }
#endif

        public static PublicPoint ValidatePublicKeyFullExport(byte[] pk, int pkOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ValidatePublicKeyFullExport(pk.AsSpan(pkOff));
#else
            byte[] A = Copy(pk, pkOff, PublicKeySize);

            if (!CheckPointFullVar(A))
                return null;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, false, ref pA))
                return null;

            if (!CheckPointOrderVar(ref pA))
                return null;

            return ExportPoint(ref pA);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static PublicPoint ValidatePublicKeyFullExport(ReadOnlySpan<byte> pk)
        {
            Span<byte> A = stackalloc byte[PublicKeySize];
            A.CopyFrom(pk);

            if (!CheckPointFullVar(A))
                return null;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, false, ref pA))
                return null;

            if (!CheckPointOrderVar(ref pA))
                return null;

            return ExportPoint(ref pA);
        }
#endif

        public static bool ValidatePublicKeyPartial(byte[] pk, int pkOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ValidatePublicKeyPartial(pk.AsSpan(pkOff));
#else
            byte[] A = Copy(pk, pkOff, PublicKeySize);

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pA);
            return DecodePointVar(A, false, ref pA);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool ValidatePublicKeyPartial(ReadOnlySpan<byte> pk)
        {
            Span<byte> A = stackalloc byte[PublicKeySize];
            A.CopyFrom(pk);

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pA);
            return DecodePointVar(A, false, ref pA);
        }
#endif

        public static PublicPoint ValidatePublicKeyPartialExport(byte[] pk, int pkOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ValidatePublicKeyPartialExport(pk.AsSpan(pkOff));
#else
            byte[] A = Copy(pk, pkOff, PublicKeySize);

            if (!CheckPointFullVar(A))
                return null;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, false, ref pA))
                return null;

            return ExportPoint(ref pA);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static PublicPoint ValidatePublicKeyPartialExport(ReadOnlySpan<byte> pk)
        {
            Span<byte> A = stackalloc byte[PublicKeySize];
            A.CopyFrom(pk);

            if (!CheckPointFullVar(A))
                return null;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, false, ref pA))
                return null;

            return ExportPoint(ref pA);
        }
#endif

        public static bool Verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff,
            int mLen)
        {
            byte phflag = 0x00;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
        }

        public static bool Verify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte[] m, int mOff,
            int mLen)
        {
            byte phflag = 0x00;

            return ImplVerify(sig, sigOff, publicPoint, ctx, phflag, m, mOff, mLen);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff)
        {
            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, ph, phOff, PrehashSize);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte[] ph,
            int phOff)
        {
            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, publicPoint, ctx, phflag, ph, phOff, PrehashSize);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, IXof ph)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.OutputFinal(m, 0, PrehashSize))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, 0, m.Length);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, IXof ph)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.OutputFinal(m, 0, PrehashSize))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, publicPoint, ctx, phflag, m, 0, m.Length);
        }
    }
}
