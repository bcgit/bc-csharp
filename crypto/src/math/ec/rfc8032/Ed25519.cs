using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    using F = Rfc7748.X25519Field;

    /// <summary>
    /// A low-level implementation of the Ed25519, Ed25519ctx, and Ed25519ph instantiations of the Edwards-Curve Digital
    /// Signature Algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
    /// </summary>
    /// <remarks>
    /// The implementation strategy is mostly drawn from <a href="https://ia.cr/2012/309">
    /// Mike Hamburg, "Fast and compact elliptic-curve cryptography"</a>, notably the "signed multi-comb" algorithm (for
    /// scalar multiplication by a fixed point), the "half Niels coordinates" (for precomputed points), and the
    /// "extensible coordinates" (for accumulators). Standard
    /// <a href="https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html">extended coordinates</a> are used during
    /// precomputations, needing only a single extra point addition formula.
    /// </remarks>
    public static class Ed25519
    {
        // -x^2 + y^2 == 1 + 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3 * x^2 * y^2

        public enum Algorithm
        {
            Ed25519 = 0,
            Ed25519ctx = 1,
            Ed25519ph = 2,
        }

        public sealed class PublicPoint
        {
            internal readonly int[] m_data;

            internal PublicPoint(int[] data)
            {
                m_data = data;
            }
        }

        private const int CoordUints = 8;
        private const int PointBytes = CoordUints * 4;
        private const int ScalarUints = 8;
        private const int ScalarBytes = ScalarUints * 4;

        public static readonly int PrehashSize = 64;
        public static readonly int PublicKeySize = PointBytes;
        public static readonly int SecretKeySize = 32;
        public static readonly int SignatureSize = PointBytes + ScalarBytes;

        // "SigEd25519 no Ed25519 collisions"
        private static readonly byte[] Dom2Prefix = { 0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20,
            0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69, 0x73, 0x69,
            0x6f, 0x6e, 0x73 };

        private static readonly uint[] P = { 0xFFFFFFEDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
            0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU };

        private static readonly uint[] Order8_y1 = { 0x706A17C7U, 0x4FD84D3DU, 0x760B3CBAU, 0x0F67100DU, 0xFA53202AU,
            0xC6CC392CU, 0x77FDC74EU, 0x7A03AC92U };
        private static readonly uint[] Order8_y2 = { 0x8F95E826U, 0xB027B2C2U, 0x89F4C345U, 0xF098EFF2U, 0x05ACDFD5U,
            0x3933C6D3U, 0x880238B1U, 0x05FC536DU };

        private static readonly int[] B_x = { 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
            0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };
        private static readonly int[] B_y = { 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
            0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };

        // 2^128 * B
        private static readonly int[] B128_x = { 0x00B7E824, 0x0011EB98, 0x003E5FC8, 0x024E1739, 0x0131CD0B, 0x014E29A0,
            0x034E6138, 0x0132C952, 0x03F9E22F, 0x00984F5F };
        private static readonly int[] B128_y = { 0x03F5A66B, 0x02AF4452, 0x0049E5BB, 0x00F28D26, 0x0121A17C, 0x02C29C3A,
            0x0047AD89, 0x0087D95F, 0x0332936E, 0x00BE5933 };

        // Note that d == -121665/121666
        private static readonly int[] C_d = { 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898,
            0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
        private static readonly int[] C_d2 = { 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130,
            0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };
        private static readonly int[] C_d4 = { 0x0165E2B2, 0x034DCA13, 0x002ADD7A, 0x01A8283B, 0x00038052, 0x01E7A260,
            0x03407977, 0x019CE331, 0x01C56DFF, 0x00901B67 };

        //private const int WnafWidth = 5;
        private const int WnafWidth128 = 4;
        private const int WnafWidthBase = 6;

        // ScalarMultBase is hard-coded for these values of blocks, teeth, spacing so they can't be freely changed
        private const int PrecompBlocks = 8;
        private const int PrecompTeeth = 4;
        private const int PrecompSpacing = 8;
        private const int PrecompRange = PrecompBlocks * PrecompTeeth * PrecompSpacing; // range == 256
        private const int PrecompPoints = 1 << (PrecompTeeth - 1);
        private const int PrecompMask = PrecompPoints - 1;

        private static readonly object PrecompLock = new object();
        private static PointPrecomp[] PrecompBaseWnaf = null;
        private static PointPrecomp[] PrecompBase128Wnaf = null;
        private static int[] PrecompBaseComb = null;

        private struct PointAccum
        {
            internal int[] x, y, z, u, v;
        }

        private struct PointAffine
        {
            internal int[] x, y;
        }

        private struct PointExtended
        {
            internal int[] x, y, z, t;
        }

        private struct PointPrecomp
        {
            internal int[] ymx_h;       // (y - x)/2
            internal int[] ypx_h;       // (y + x)/2
            internal int[] xyd;         // x.y.d
        }

        private struct PointPrecompZ
        {
            internal int[] ymx_h;       // (y - x)/2
            internal int[] ypx_h;       // (y + x)/2
            internal int[] xyd;         // x.y.d
            internal int[] z;
        }

        // Temp space to avoid allocations in point formulae.
        private struct PointTemp
        {
            internal int[] r0, r1;
        }

        private static byte[] CalculateS(byte[] r, byte[] k, byte[] s)
        {
            uint[] t = new uint[ScalarUints * 2];   Scalar25519.Decode(r, t);
            uint[] u = new uint[ScalarUints];       Scalar25519.Decode(k, u);
            uint[] v = new uint[ScalarUints];       Scalar25519.Decode(s, v);

            Nat256.MulAddTo(u, v, t);

            byte[] result = new byte[ScalarBytes * 2];
            Codec.Encode32(t, 0, t.Length, result, 0);
            return Scalar25519.Reduce(result);
        }

        private static bool CheckContextVar(byte[] ctx, byte phflag)
        {
            return ctx == null && phflag == 0x00
                || ctx != null && ctx.Length < 256;
        }

        private static int CheckPoint(ref PointAffine p)
        {
            int[] t = F.Create();
            int[] u = F.Create();
            int[] v = F.Create();

            F.Sqr(p.x, u);
            F.Sqr(p.y, v);
            F.Mul(u, v, t);
            F.Sub(v, u, v);
            F.Mul(t, C_d, t);
            F.AddOne(t);
            F.Sub(t, v, t);
            F.Normalize(t);

            return F.IsZero(t);
        }

        private static int CheckPoint(PointAccum p)
        {
            int[] t = F.Create();
            int[] u = F.Create();
            int[] v = F.Create();
            int[] w = F.Create();

            F.Sqr(p.x, u);
            F.Sqr(p.y, v);
            F.Sqr(p.z, w);
            F.Mul(u, v, t);
            F.Sub(v, u, v);
            F.Mul(v, w, v);
            F.Sqr(w, w);
            F.Mul(t, C_d, t);
            F.Add(t, w, t);
            F.Sub(t, v, t);
            F.Normalize(t);

            return F.IsZero(t);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static bool CheckPointFullVar(ReadOnlySpan<byte> p)
        {
            uint y7 = Codec.Decode32(p[28..]) & 0x7FFFFFFFU;

            uint t0 = y7;
            uint t1 = y7 ^ P[7];
            uint t2 = y7 ^ Order8_y1[7];
            uint t3 = y7 ^ Order8_y2[7];

            for (int i = CoordUints - 2; i > 0; --i)
            {
                uint yi = Codec.Decode32(p[(i * 4)..]);

                t0 |= yi;
                t1 |= yi ^ P[i];
                t2 |= yi ^ Order8_y1[i];
                t3 |= yi ^ Order8_y2[i];
            }

            uint y0 = Codec.Decode32(p);

            // Reject 0 and 1
            if (t0 == 0 && y0 <= 1U)
                return false;

            // Reject P - 1 and non-canonical encodings (i.e. >= P)
            if (t1 == 0 && y0 >= (P[0] - 1U))
                return false;

            t2 |= y0 ^ Order8_y1[0];
            t3 |= y0 ^ Order8_y2[0];

            // Reject order 8 points
            return (t2 != 0) & (t3 != 0);
        }
#else
        private static bool CheckPointFullVar(byte[] p)
        {
            uint y7 = Codec.Decode32(p, 28) & 0x7FFFFFFFU;

            uint t0 = y7;
            uint t1 = y7 ^ P[7];
            uint t2 = y7 ^ Order8_y1[7];
            uint t3 = y7 ^ Order8_y2[7];

            for (int i = CoordUints - 2; i > 0; --i)
            {
                uint yi = Codec.Decode32(p, i * 4);

                t0 |= yi;
                t1 |= yi ^ P[i];
                t2 |= yi ^ Order8_y1[i];
                t3 |= yi ^ Order8_y2[i];
            }

            uint y0 = Codec.Decode32(p, 0);

            // Reject 0 and 1
            if (t0 == 0 && y0 <= 1U)
                return false;

            // Reject P - 1 and non-canonical encodings (i.e. >= P)
            if (t1 == 0 && y0 >= (P[0] - 1U))
                return false;

            t2 |= y0 ^ Order8_y1[0];
            t3 |= y0 ^ Order8_y2[0];

            // Reject order 8 points
            return (t2 != 0) & (t3 != 0);
        }
#endif

        private static bool CheckPointOrderVar(ref PointAffine p)
        {
            Init(out PointAccum r);
            ScalarMultOrderVar(ref p, ref r);
            return NormalizeToNeutralElementVar(ref r);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static bool CheckPointVar(ReadOnlySpan<byte> p)
        {
            if ((Codec.Decode32(p[28..]) & 0x7FFFFFFFU) < P[7])
                return true;
            for (int i = CoordUints - 2; i >= 0; --i)
            {
                if (Codec.Decode32(p[(i * 4)..]) < P[i])
                    return true;
            }
            return false;
        }
#else
        private static bool CheckPointVar(byte[] p)
        {
            if ((Codec.Decode32(p, 28) & 0x7FFFFFFFU) < P[7])
                return true;
            for (int i = CoordUints - 2; i >= 0; --i)
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

        private static IDigest CreateDigest()
        {
            var d = new Sha512Digest();
            if (d.GetDigestSize() != 64)
                throw new InvalidOperationException();
            return d;
        }

        public static IDigest CreatePrehash()
        {
            return CreateDigest();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static bool DecodePointVar(ReadOnlySpan<byte> p, bool negate, ref PointAffine r)
#else
        private static bool DecodePointVar(byte[] p, bool negate, ref PointAffine r)
#endif
        {
            int x_0 = (p[PointBytes - 1] & 0x80) >> 7;

            F.Decode(p, r.y);

            int[] u = F.Create();
            int[] v = F.Create();

            F.Sqr(r.y, u);
            F.Mul(C_d, u, v);
            F.SubOne(u);
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

        private static void Dom2(IDigest d, byte phflag, byte[] ctx)
        {
            Debug.Assert(ctx != null);

            int n = Dom2Prefix.Length;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> t = stackalloc byte[n + 2 + ctx.Length];
            Dom2Prefix.CopyTo(t);
            t[n] = phflag;
            t[n + 1] = (byte)ctx.Length;
            ctx.CopyTo(t.Slice(n + 2));

            d.BlockUpdate(t);
#else
            byte[] t = new byte[n + 2 + ctx.Length];
            Dom2Prefix.CopyTo(t, 0);
            t[n] = phflag;
            t[n + 1] = (byte)ctx.Length;
            ctx.CopyTo(t, n + 2);

            d.BlockUpdate(t, 0, t.Length);
#endif
        }

        private static void EncodePoint(ref PointAffine p, byte[] r, int rOff)
        {
            F.Encode(p.y, r, rOff);
            r[rOff + PointBytes - 1] |= (byte)((p.x[0] & 1) << 7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void EncodePoint(ref PointAffine p, Span<byte> r)
        {
            F.Encode(p.y, r);
            r[PointBytes - 1] |= (byte)((p.x[0] & 1) << 7);
        }
#endif

        public static void EncodePublicPoint(PublicPoint publicPoint, byte[] pk, int pkOff)
        {
            F.Encode(publicPoint.m_data, F.Size, pk, pkOff);
            pk[pkOff + PointBytes - 1] |= (byte)((publicPoint.m_data[0] & 1) << 7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void EncodePublicPoint(PublicPoint publicPoint, Span<byte> pk)
        {
            F.Encode(publicPoint.m_data.AsSpan(F.Size), pk);
            pk[PointBytes - 1] |= (byte)((publicPoint.m_data[0] & 1) << 7);
        }
#endif

        private static int EncodeResult(ref PointAccum p, byte[] r, int rOff)
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
        private static int EncodeResult(ref PointAccum p, Span<byte> r)
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
            int[] data = new int[F.Size * 2];
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
            IDigest d = CreateDigest();
            byte[] h = new byte[64];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.DoFinal(h, 0);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            ScalarMultBaseEncoded(s, pk, pkOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void GeneratePublicKey(ReadOnlySpan<byte> sk, Span<byte> pk)
        {
            IDigest d = CreateDigest();
            Span<byte> h = stackalloc byte[64];

            d.BlockUpdate(sk[..SecretKeySize]);
            d.DoFinal(h);

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
            IDigest d = CreateDigest();
            byte[] h = new byte[64];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.DoFinal(h, 0);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            Init(out PointAccum p);
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
            IDigest d = CreateDigest();
            Span<byte> h = stackalloc byte[64];

            d.BlockUpdate(sk[..SecretKeySize]);
            d.DoFinal(h);

            Span<byte> s = stackalloc byte[ScalarBytes];
            PruneScalar(h, s);

            Init(out PointAccum p);
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

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void GroupCombBits(Span<uint> n)
#else
        private static void GroupCombBits(uint[] n)
#endif
        {
            /*
             * Because we are using 4 teeth and 8 spacing, each limb of n corresponds to one of the 8 blocks.
             * Therefore we can efficiently group the bits for each comb position using a (double) shuffle. 
             */
            for (int i = 0; i < n.Length; ++i)
            {
                n[i] = Interleave.Shuffle2(n[i]);
            }
        }

        private static void ImplSign(IDigest d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag,
            byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            if (ctx != null)
            {
                Dom2(d, phflag, ctx);
            }
            d.BlockUpdate(h, ScalarBytes, ScalarBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] r = Scalar25519.Reduce(h);
            byte[] R = new byte[PointBytes];
            ScalarMultBaseEncoded(r, R, 0);

            if (ctx != null)
            {
                Dom2(d, phflag, ctx);
            }
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(pk, pkOff, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] k = Scalar25519.Reduce(h);
            byte[] S = CalculateS(r, k, s);

            Array.Copy(R, 0, sig, sigOff, PointBytes);
            Array.Copy(S, 0, sig, sigOff + PointBytes, ScalarBytes);
        }

        private static void ImplSign(byte[] sk, int skOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen,
            byte[] sig, int sigOff)
        {
            if (!CheckContextVar(ctx, phflag))
                throw new ArgumentException("ctx");

            IDigest d = CreateDigest();
            byte[] h = new byte[64];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.DoFinal(h, 0);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            byte[] pk = new byte[PointBytes];
            ScalarMultBaseEncoded(s, pk, 0);

            ImplSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        private static void ImplSign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
            int mOff, int mLen, byte[] sig, int sigOff)
        {
            if (!CheckContextVar(ctx, phflag))
                throw new ArgumentException("ctx");

            IDigest d = CreateDigest();
            byte[] h = new byte[64];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.DoFinal(h, 0);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            ImplSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        private static bool ImplVerify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m,
            int mOff, int mLen)
        {
            if (!CheckContextVar(ctx, phflag))
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
            if (!Scalar25519.CheckVar(S, nS))
                return false;

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, true, ref pA))
                return false;

            IDigest d = CreateDigest();
            Span<byte> h = stackalloc byte[64];

            if (ctx != null)
            {
                Dom2(d, phflag, ctx);
            }
            d.BlockUpdate(R);
            d.BlockUpdate(A);
            d.BlockUpdate(m.AsSpan(mOff, mLen));
            d.DoFinal(h);

            Span<byte> k = stackalloc byte[ScalarBytes];
            Scalar25519.Reduce(h, k);

            Span<uint> nA = stackalloc uint[ScalarUints];
            Scalar25519.Decode(k, nA);

            Span<uint> v0 = stackalloc uint[4];
            Span<uint> v1 = stackalloc uint[4];
#else
            byte[] R = Copy(sig, sigOff, PointBytes);
            byte[] S = Copy(sig, sigOff + PointBytes, ScalarBytes);
            byte[] A = Copy(pk, pkOff, PublicKeySize);

            if (!CheckPointVar(R))
                return false;

            uint[] nS = new uint[ScalarUints];
            if (!Scalar25519.CheckVar(S, nS))
                return false;

            if (!CheckPointFullVar(A))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            if (!DecodePointVar(A, true, ref pA))
                return false;

            IDigest d = CreateDigest();
            byte[] h = new byte[64];

            if (ctx != null)
            {
                Dom2(d, phflag, ctx);
            }
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(A, 0, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] k = Scalar25519.Reduce(h);

            uint[] nA = new uint[ScalarUints];
            Scalar25519.Decode(k, nA);

            uint[] v0 = new uint[4];
            uint[] v1 = new uint[4];
#endif

            Scalar25519.ReduceBasisVar(nA, v0, v1);
            Scalar25519.Multiply128Var(nS, v1, nS);

            Init(out PointAccum pZ);
            ScalarMultStraus128Var(nS, v0, ref pA, v1, ref pR, ref pZ);
            return NormalizeToNeutralElementVar(ref pZ);
        }

        private static bool ImplVerify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, byte phflag,
            byte[] m, int mOff, int mLen)
        {
            if (!CheckContextVar(ctx, phflag))
                throw new ArgumentException("ctx");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> signature = stackalloc byte[SignatureSize];
            signature.CopyFrom(sig.AsSpan(sigOff, SignatureSize));
            var R = signature[..PointBytes];
            var S = signature[PointBytes..];

            if (!CheckPointVar(R))
                return false;

            Span<uint> nS = stackalloc uint[ScalarUints];
            if (!Scalar25519.CheckVar(S, nS))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            F.Negate(publicPoint.m_data, pA.x);
            F.Copy(publicPoint.m_data.AsSpan(F.Size), pA.y);

            Span<byte> A = stackalloc byte[PublicKeySize];
            EncodePublicPoint(publicPoint, A);

            IDigest d = CreateDigest();
            Span<byte> h = stackalloc byte[64];

            if (ctx != null)
            {
                Dom2(d, phflag, ctx);
            }
            d.BlockUpdate(R);
            d.BlockUpdate(A);
            d.BlockUpdate(m.AsSpan(mOff, mLen));
            d.DoFinal(h);

            Span<byte> k = stackalloc byte[ScalarBytes];
            Scalar25519.Reduce(h, k);

            Span<uint> nA = stackalloc uint[ScalarUints];
            Scalar25519.Decode(k, nA);

            Span<uint> v0 = stackalloc uint[4];
            Span<uint> v1 = stackalloc uint[4];
#else
            byte[] R = Copy(sig, sigOff, PointBytes);
            byte[] S = Copy(sig, sigOff + PointBytes, ScalarBytes);

            if (!CheckPointVar(R))
                return false;

            uint[] nS = new uint[ScalarUints];
            if (!Scalar25519.CheckVar(S, nS))
                return false;

            Init(out PointAffine pR);
            if (!DecodePointVar(R, true, ref pR))
                return false;

            Init(out PointAffine pA);
            F.Negate(publicPoint.m_data, pA.x);
            F.Copy(publicPoint.m_data, F.Size, pA.y, 0);

            byte[] A = new byte[PublicKeySize];
            EncodePublicPoint(publicPoint, A, 0);

            IDigest d = CreateDigest();
            byte[] h = new byte[64];

            if (ctx != null)
            {
                Dom2(d, phflag, ctx);
            }
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(A, 0, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] k = Scalar25519.Reduce(h);

            uint[] nA = new uint[ScalarUints];
            Scalar25519.Decode(k, nA);

            uint[] v0 = new uint[4];
            uint[] v1 = new uint[4];
#endif

            Scalar25519.ReduceBasisVar(nA, v0, v1);
            Scalar25519.Multiply128Var(nS, v1, nS);

            Init(out PointAccum pZ);
            ScalarMultStraus128Var(nS, v0, ref pA, v1, ref pR, ref pZ);
            return NormalizeToNeutralElementVar(ref pZ);
        }

        private static void Init(out PointAccum r)
        {
            r.x = F.Create();
            r.y = F.Create();
            r.z = F.Create();
            r.u = F.Create();
            r.v = F.Create();
        }

        private static void Init(out PointAffine r)
        {
            r.x = F.Create();
            r.y = F.Create();
        }

        private static void Init(out PointExtended r)
        {
            r.x = F.Create();
            r.y = F.Create();
            r.z = F.Create();
            r.t = F.Create();
        }

        private static void Init(out PointPrecomp r)
        {
            r.ymx_h = F.Create();
            r.ypx_h = F.Create();
            r.xyd = F.Create();
        }

        private static void Init(out PointPrecompZ r)
        {
            r.ymx_h = F.Create();
            r.ypx_h = F.Create();
            r.xyd = F.Create();
            r.z = F.Create();
        }

        private static void Init(out PointTemp r)
        {
            r.r0 = F.Create();
            r.r1 = F.Create();
        }

        private static void InvertDoubleZs(PointExtended[] points)
        {
            int count = points.Length;
            int[] cs = F.CreateTable(count);

            int[] u = F.Create();
            F.Copy(points[0].z, 0, u, 0);
            F.Copy(u, 0, cs, 0);

            int i = 0;
            while (++i < count)
            {
                F.Mul(u, points[i].z, u);
                F.Copy(u, 0, cs, i * F.Size);
            }

            F.Add(u, u, u);
            F.InvVar(u, u);
            --i;

            int[] t = F.Create();

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

        private static void NormalizeToAffine(ref PointAccum p, ref PointAffine r)
        {
            F.Inv(p.z, r.y);
            F.Mul(r.y, p.x, r.x);
            F.Mul(r.y, p.y, r.y);
            F.Normalize(r.x);
            F.Normalize(r.y);
        }

        private static bool NormalizeToNeutralElementVar(ref PointAccum p)
        {
            F.Normalize(p.x);
            F.Normalize(p.y);
            F.Normalize(p.z);

            return F.IsZeroVar(p.x) && F.AreEqualVar(p.y, p.z);
        }

        private static void PointAdd(ref PointExtended p, ref PointExtended q, ref PointExtended r, ref PointTemp t)
        {
            // p may ref the same point as r (or q), but q may not ref the same point as r.
            Debug.Assert(q.x != r.x & q.y != r.y && q.z != r.z && q.t != r.t);

            int[] a = r.x;
            int[] b = r.y;
            int[] c = t.r0;
            int[] d = t.r1;
            int[] e = a;
            int[] f = c;
            int[] g = d;
            int[] h = b;

            F.Apm(p.y, p.x, b, a);
            F.Apm(q.y, q.x, d, c);
            F.Mul(a, c, a);
            F.Mul(b, d, b);
            F.Mul(p.t, q.t, c);
            F.Mul(c, C_d2, c);
            F.Add(p.z, p.z, d);
            F.Mul(d, q.z, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, g, f);
            F.Mul(e, h, r.t);
            F.Mul(f, g, r.z);
            F.Mul(e, f, r.x);
            F.Mul(h, g, r.y);
        }

        private static void PointAdd(ref PointPrecomp p, ref PointAccum r, ref PointTemp t)
        {
            int[] a = r.x;
            int[] b = r.y;
            int[] c = t.r0;
            int[] e = r.u;
            int[] f = a;
            int[] g = b;
            int[] h = r.v;

            F.Apm(r.y, r.x, b, a);
            F.Mul(a, p.ymx_h, a);
            F.Mul(b, p.ypx_h, b);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.xyd, c);
            F.Apm(b, a, h, e);
            F.Apm(r.z, c, g, f);
            F.Mul(f, g, r.z);
            F.Mul(f, e, r.x);
            F.Mul(g, h, r.y);
        }

        private static void PointAdd(ref PointPrecompZ p, ref PointAccum r, ref PointTemp t)
        {
            int[] a = r.x;
            int[] b = r.y;
            int[] c = t.r0;
            int[] d = r.z;
            int[] e = r.u;
            int[] f = a;
            int[] g = b;
            int[] h = r.v;

            F.Apm(r.y, r.x, b, a);
            F.Mul(a, p.ymx_h, a);
            F.Mul(b, p.ypx_h, b);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.xyd, c);
            F.Mul(r.z, p.z, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, g, f);
            F.Mul(f, g, r.z);
            F.Mul(f, e, r.x);
            F.Mul(g, h, r.y);
        }

        private static void PointAddVar(bool negate, ref PointPrecomp p, ref PointAccum r, ref PointTemp t)
        {
            int[] a = r.x;
            int[] b = r.y;
            int[] c = t.r0;
            int[] e = r.u;
            int[] f = a;
            int[] g = b;
            int[] h = r.v;

            int[] na, nb;
            if (negate)
            {
                na = b; nb = a;
            }
            else
            {
                na = a; nb = b;
            }
            int[] nf = na, ng = nb;

            F.Apm(r.y, r.x, b, a);
            F.Mul(na, p.ymx_h, na);
            F.Mul(nb, p.ypx_h, nb);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.xyd, c);
            F.Apm(b, a, h, e);
            F.Apm(r.z, c, ng, nf);
            F.Mul(f, g, r.z);
            F.Mul(f, e, r.x);
            F.Mul(g, h, r.y);
        }

        private static void PointAddVar(bool negate, ref PointPrecompZ p, ref PointAccum r, ref PointTemp t)
        {
            int[] a = r.x;
            int[] b = r.y;
            int[] c = t.r0;
            int[] d = r.z;
            int[] e = r.u;
            int[] f = a;
            int[] g = b;
            int[] h = r.v;

            int[] na, nb;
            if (negate)
            {
                na = b; nb = a;
            }
            else
            {
                na = a; nb = b;
            }
            int[] nf = na, ng = nb;

            F.Apm(r.y, r.x, b, a);
            F.Mul(na, p.ymx_h, na);
            F.Mul(nb, p.ypx_h, nb);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.xyd, c);
            F.Mul(r.z, p.z, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, ng, nf);
            F.Mul(f, g, r.z);
            F.Mul(f, e, r.x);
            F.Mul(g, h, r.y);
        }

        private static void PointCopy(ref PointAccum p, ref PointExtended r)
        {
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            F.Copy(p.z, 0, r.z, 0);
            F.Mul(p.u, p.v, r.t);
        }

        private static void PointCopy(ref PointAffine p, ref PointExtended r)
        {
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            F.One(r.z);
            F.Mul(p.x, p.y, r.t);
        }

        private static void PointCopy(ref PointExtended p, ref PointPrecompZ r)
        {
            // To avoid halving x and y, we double t and z instead.
            F.Apm(p.y, p.x, r.ypx_h, r.ymx_h);
            F.Mul(p.t, C_d2, r.xyd);
            F.Add(p.z, p.z, r.z);
        }

        private static void PointDouble(ref PointAccum r)
        {
            int[] a = r.x;
            int[] b = r.y;
            int[] c = r.z;
            int[] e = r.u;
            int[] f = a;
            int[] g = b;
            int[] h = r.v;

            F.Add(r.x, r.y, e);
            F.Sqr(r.x, a);
            F.Sqr(r.y, b);
            F.Sqr(r.z, c);
            F.Add(c, c, c);
            F.Apm(a, b, h, g);
            F.Sqr(e, e);
            F.Sub(h, e, e);
            F.Add(c, g, f);
            F.Carry(f); // Probably unnecessary, but keep until better bounds analysis available
            F.Mul(f, g, r.z);
            F.Mul(f, e, r.x);
            F.Mul(g, h, r.y);
        }

        private static void PointLookup(int block, int index, ref PointPrecomp p)
        {
            Debug.Assert(0 <= block && block < PrecompBlocks);
            Debug.Assert(0 <= index && index < PrecompPoints);

            int off = block * PrecompPoints * 3 * F.Size;

            for (int i = 0; i < PrecompPoints; ++i)
            {
                int cond = ((i ^ index) - 1) >> 31;
                F.CMov(cond, PrecompBaseComb, off, p.ymx_h, 0);     off += F.Size;
                F.CMov(cond, PrecompBaseComb, off, p.ypx_h, 0);     off += F.Size;
                F.CMov(cond, PrecompBaseComb, off, p.xyd  , 0);     off += F.Size;
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void PointLookupZ(ReadOnlySpan<uint> x, int n, ReadOnlySpan<int> table, ref PointPrecompZ r)
        {
            // TODO This method is currently hard-coded to 4-bit windows and 8 precomputed points

            uint w = GetWindow4(x, n);

            int sign = (int)(w >> (4 - 1)) ^ 1;
            int abs = ((int)w ^ -sign) & 7;

            Debug.Assert(sign == 0 || sign == 1);
            Debug.Assert(0 <= abs && abs < 8);

            for (int i = 0; i < 8; ++i)
            {
                int cond = ((i ^ abs) - 1) >> 31;
                F.CMov(cond, table, r.ymx_h);       table = table[F.Size..];
                F.CMov(cond, table, r.ypx_h);       table = table[F.Size..];
                F.CMov(cond, table, r.xyd);         table = table[F.Size..];
                F.CMov(cond, table, r.z);           table = table[F.Size..];
            }

            F.CSwap(sign, r.ymx_h, r.ypx_h);
            F.CNegate(sign, r.xyd);
        }
#else
        private static void PointLookupZ(uint[] x, int n, int[] table, ref PointPrecompZ r)
        {
            // TODO This method is currently hard-coded to 4-bit windows and 8 precomputed points

            uint w = GetWindow4(x, n);

            int sign = (int)(w >> (4 - 1)) ^ 1;
            int abs = ((int)w ^ -sign) & 7;

            Debug.Assert(sign == 0 || sign == 1);
            Debug.Assert(0 <= abs && abs < 8);

            for (int i = 0, off = 0; i < 8; ++i)
            {
                int cond = ((i ^ abs) - 1) >> 31;
                F.CMov(cond, table, off, r.ymx_h, 0);       off += F.Size;
                F.CMov(cond, table, off, r.ypx_h, 0);       off += F.Size;
                F.CMov(cond, table, off, r.xyd  , 0);       off += F.Size;
                F.CMov(cond, table, off, r.z    , 0);       off += F.Size;
            }

            F.CSwap(sign, r.ymx_h, r.ypx_h);
            F.CNegate(sign, r.xyd);
        }
#endif

        private static void PointPrecompute(ref PointAffine p, PointExtended[] points, int pointsOff, int pointsLen,
            ref PointTemp t)
        {
            Debug.Assert(pointsLen > 0);

            Init(out points[pointsOff]);
            PointCopy(ref p, ref points[pointsOff]);

            Init(out PointExtended d);
            PointAdd(ref points[pointsOff], ref points[pointsOff], ref d, ref t);

            for (int i = 1; i < pointsLen; ++i)
            {
                Init(out points[pointsOff + i]);
                PointAdd(ref points[pointsOff + i - 1], ref d, ref points[pointsOff + i], ref t);
            }
        }

        private static int[] PointPrecomputeZ(ref PointAffine p, int count, ref PointTemp t)
        {
            Debug.Assert(count > 0);

            Init(out PointExtended q);
            PointCopy(ref p, ref q);

            Init(out PointExtended d);
            PointAdd(ref q, ref q, ref d, ref t);

            Init(out PointPrecompZ r);
            int[] table = F.CreateTable(count * 4);
            int off = 0;

            int i = 0;
            for (;;)
            {
                PointCopy(ref q, ref r);

                F.Copy(r.ymx_h, 0, table, off);     off += F.Size;
                F.Copy(r.ypx_h, 0, table, off);     off += F.Size;
                F.Copy(r.xyd  , 0, table, off);     off += F.Size;
                F.Copy(r.z    , 0, table, off);     off += F.Size;

                if (++i == count)
                    break;

                PointAdd(ref q, ref d, ref q, ref t);
            }

            return table;
        }

        private static void PointPrecomputeZ(ref PointAffine p, PointPrecompZ[] points, int count, ref PointTemp t)
        {
            Debug.Assert(count > 0);

            Init(out PointExtended q);
            PointCopy(ref p, ref q);

            Init(out PointExtended d);
            PointAdd(ref q, ref q, ref d, ref t);

            int i = 0;
            for (;;)
            {
                ref PointPrecompZ r = ref points[i];
                Init(out r);
                PointCopy(ref q, ref r);

                if (++i == count)
                    break;

                PointAdd(ref q, ref d, ref q, ref t);
            }
        }

        private static void PointSetNeutral(ref PointAccum p)
        {
            F.Zero(p.x);
            F.One(p.y);
            F.One(p.z);
            F.Zero(p.u);
            F.One(p.v);
        }

        public static void Precompute()
        {
            lock (PrecompLock)
            {
                if (PrecompBaseComb != null)
                    return;

                int wnafPoints = 1 << (WnafWidthBase - 2);
                int combPoints = PrecompBlocks * PrecompPoints;
                int totalPoints = wnafPoints * 2 + combPoints;

                PointExtended[] points = new PointExtended[totalPoints];
                Init(out PointTemp t);

                Init(out PointAffine B);
                F.Copy(B_x, 0, B.x, 0);
                F.Copy(B_y, 0, B.y, 0);

                PointPrecompute(ref B, points, 0, wnafPoints, ref t);

                Init(out PointAffine B128);
                F.Copy(B128_x, 0, B128.x, 0);
                F.Copy(B128_y, 0, B128.y, 0);

                PointPrecompute(ref B128, points, wnafPoints, wnafPoints, ref t);

                Init(out PointAccum p);
                F.Copy(B_x, 0, p.x, 0);
                F.Copy(B_y, 0, p.y, 0);
                F.One(p.z);
                F.Copy(B_x, 0, p.u, 0);
                F.Copy(B_y, 0, p.v, 0);

                int pointsIndex = wnafPoints * 2;
                PointExtended[] toothPowers = new PointExtended[PrecompTeeth];
                for (int tooth = 0; tooth < PrecompTeeth; ++tooth)
                {
                    Init(out toothPowers[tooth]);
                }

                Init(out PointExtended u);
                for (int block = 0; block < PrecompBlocks; ++block)
                {
                    ref PointExtended sum = ref points[pointsIndex++];
                    Init(out sum);

                    for (int tooth = 0; tooth < PrecompTeeth; ++tooth)
                    {
                        if (tooth == 0)
                        {
                            PointCopy(ref p, ref sum);
                        }
                        else
                        {
                            PointCopy(ref p, ref u);
                            PointAdd(ref sum, ref u, ref sum, ref t);
                        }

                        PointDouble(ref p);
                        PointCopy(ref p, ref toothPowers[tooth]);

                        if (block + tooth != PrecompBlocks + PrecompTeeth - 2)
                        {
                            for (int spacing = 1; spacing < PrecompSpacing; ++spacing)
                            {
                                PointDouble(ref p);
                            }
                        }
                    }

                    F.Negate(sum.x, sum.x);
                    F.Negate(sum.t, sum.t);

                    for (int tooth = 0; tooth < (PrecompTeeth - 1); ++tooth)
                    {
                        int size = 1 << tooth;
                        for (int j = 0; j < size; ++j, ++pointsIndex)
                        {
                            Init(out points[pointsIndex]);
                            PointAdd(ref points[pointsIndex - size], ref toothPowers[tooth], ref points[pointsIndex],
                                ref t);
                        }
                    }
                }
                Debug.Assert(pointsIndex == totalPoints);

                // Set each z coordinate to 1/(2.z) to avoid calculating halves of x, y in the following code
                InvertDoubleZs(points);

                PrecompBaseWnaf = new PointPrecomp[wnafPoints];
                for (int i = 0; i < wnafPoints; ++i)
                {
                    ref PointExtended q = ref points[i];
                    ref PointPrecomp r = ref PrecompBaseWnaf[i];
                    Init(out r);

                    // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
                    F.Mul(q.x, q.z, q.x);
                    F.Mul(q.y, q.z, q.y);

                    // y/2 +/- x/2
                    F.Apm(q.y, q.x, r.ypx_h, r.ymx_h);

                    // x/2 * y/2 * (4.d) == x.y.d
                    F.Mul(q.x, q.y, r.xyd);
                    F.Mul(r.xyd, C_d4, r.xyd);

                    F.Normalize(r.ymx_h);
                    F.Normalize(r.ypx_h);
                    F.Normalize(r.xyd);
                }

                PrecompBase128Wnaf = new PointPrecomp[wnafPoints];
                for (int i = 0; i < wnafPoints; ++i)
                {
                    ref PointExtended q = ref points[wnafPoints + i];
                    ref PointPrecomp r = ref PrecompBase128Wnaf[i];
                    Init(out r);

                    // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
                    F.Mul(q.x, q.z, q.x);
                    F.Mul(q.y, q.z, q.y);

                    // y/2 +/- x/2
                    F.Apm(q.y, q.x, r.ypx_h, r.ymx_h);

                    // x/2 * y/2 * (4.d) == x.y.d
                    F.Mul(q.x, q.y, r.xyd);
                    F.Mul(r.xyd, C_d4, r.xyd);

                    F.Normalize(r.ymx_h);
                    F.Normalize(r.ypx_h);
                    F.Normalize(r.xyd);
                }

                PrecompBaseComb = F.CreateTable(combPoints * 3);
                Init(out PointPrecomp s);
                int off = 0;
                for (int i = wnafPoints * 2; i < totalPoints; ++i)
                {
                    ref PointExtended q = ref points[i];

                    // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
                    F.Mul(q.x, q.z, q.x);
                    F.Mul(q.y, q.z, q.y);

                    // y/2 +/- x/2
                    F.Apm(q.y, q.x, s.ypx_h, s.ymx_h);

                    // x/2 * y/2 * (4.d) == x.y.d
                    F.Mul(q.x, q.y, s.xyd);
                    F.Mul(s.xyd, C_d4, s.xyd);

                    F.Normalize(s.ymx_h);
                    F.Normalize(s.ypx_h);
                    F.Normalize(s.xyd);

                    F.Copy(s.ymx_h, 0, PrecompBaseComb, off);       off += F.Size;
                    F.Copy(s.ypx_h, 0, PrecompBaseComb, off);       off += F.Size;
                    F.Copy(s.xyd  , 0, PrecompBaseComb, off);       off += F.Size;
                }
                Debug.Assert(off == PrecompBaseComb.Length);
            }
        }

        private static void PruneScalar(byte[] n, int nOff, byte[] r)
        {
            Array.Copy(n, nOff, r, 0, ScalarBytes);

            r[0] &= 0xF8;
            r[ScalarBytes - 1] &= 0x7F;
            r[ScalarBytes - 1] |= 0x40;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void PruneScalar(ReadOnlySpan<byte> n, Span<byte> r)
        {
            n[..ScalarBytes].CopyTo(r);

            r[0] &= 0xF8;
            r[ScalarBytes - 1] &= 0x7F;
            r[ScalarBytes - 1] |= 0x40;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMult(ReadOnlySpan<byte> k, ref PointAffine p, ref PointAccum r)
#else
        private static void ScalarMult(byte[] k, ref PointAffine p, ref PointAccum r)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> n = stackalloc uint[ScalarUints];
#else
            uint[] n = new uint[ScalarUints];
#endif

            Scalar25519.Decode(k, n);
            Scalar25519.ToSignedDigits(256, n, n);

            Init(out PointPrecompZ q);
            Init(out PointTemp t);
            int[] table = PointPrecomputeZ(ref p, 8, ref t);

            PointSetNeutral(ref r);

            int w = 63;
            for (;;)
            {
                PointLookupZ(n, w, table, ref q);
                PointAdd(ref q, ref r, ref t);

                if (--w < 0)
                    break;

                for (int i = 0; i < 4; ++i)
                {
                    PointDouble(ref r);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMultBase(ReadOnlySpan<byte> k, ref PointAccum r)
#else
        private static void ScalarMultBase(byte[] k, ref PointAccum r)
#endif
        {
            // Equivalent (but much slower)
            //Init(out PointAffine p);
            //F.Copy(B_x, 0, p.x, 0);
            //F.Copy(B_y, 0, p.y, 0);
            //ScalarMult(k, ref p, ref r);

            Precompute();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> n = stackalloc uint[ScalarUints];
#else
            uint[] n = new uint[ScalarUints];
#endif

            Scalar25519.Decode(k, n);
            Scalar25519.ToSignedDigits(PrecompRange, n, n);
            GroupCombBits(n);

            Init(out PointPrecomp p);
            Init(out PointTemp t);

            PointSetNeutral(ref r);
            int resultSign = 0;

            int cOff = (PrecompSpacing - 1) * PrecompTeeth;
            for (;;)
            {
                for (int block = 0; block < PrecompBlocks; ++block)
                {
                    uint w = n[block] >> cOff;
                    int sign = (int)(w >> (PrecompTeeth - 1)) & 1;
                    int abs = ((int)w ^ -sign) & PrecompMask;

                    Debug.Assert(sign == 0 || sign == 1);
                    Debug.Assert(0 <= abs && abs < PrecompPoints);

                    PointLookup(block, abs, ref p);

                    F.CNegate(resultSign ^ sign, r.x);
                    F.CNegate(resultSign ^ sign, r.u);
                    resultSign = sign;

                    PointAdd(ref p, ref r, ref t);
                }

                if ((cOff -= PrecompTeeth) < 0)
                    break;

                PointDouble(ref r);
            }

            F.CNegate(resultSign, r.x);
            F.CNegate(resultSign, r.u);
        }

        private static void ScalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ScalarMultBaseEncoded(k.AsSpan(), r.AsSpan(rOff));
#else
            Init(out PointAccum p);
            ScalarMultBase(k, ref p);
            if (0 == EncodeResult(ref p, r, rOff))
                throw new InvalidOperationException();
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMultBaseEncoded(ReadOnlySpan<byte> k, Span<byte> r)
        {
            Init(out PointAccum p);
            ScalarMultBase(k, ref p);
            if (0 == EncodeResult(ref p, r))
                throw new InvalidOperationException();
        }
#endif

        internal static void ScalarMultBaseYZ(byte[] k, int kOff, int[] y, int[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ScalarMultBaseYZ(k.AsSpan(kOff), y.AsSpan(), z.AsSpan());
#else
            byte[] n = new byte[ScalarBytes];
            PruneScalar(k, kOff, n);

            Init(out PointAccum p);
            ScalarMultBase(n, ref p);

            if (0 == CheckPoint(p))
                throw new InvalidOperationException();

            F.Copy(p.y, 0, y, 0);
            F.Copy(p.z, 0, z, 0);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void ScalarMultBaseYZ(ReadOnlySpan<byte> k, Span<int> y, Span<int> z)
        {
            Span<byte> n = stackalloc byte[ScalarBytes];
            PruneScalar(k, n);

            Init(out PointAccum p);
            ScalarMultBase(n, ref p);

            if (0 == CheckPoint(p))
                throw new InvalidOperationException();

            F.Copy(p.y, y);
            F.Copy(p.z, z);
        }
#endif

        private static void ScalarMultOrderVar(ref PointAffine p, ref PointAccum r)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<sbyte> ws_p = stackalloc sbyte[253];
#else
            sbyte[] ws_p = new sbyte[253];
#endif

            // NOTE: WnafWidth128 because of the special structure of the order 
            Scalar25519.GetOrderWnafVar(WnafWidth128, ws_p);

            int count = 1 << (WnafWidth128 - 2);
            PointPrecompZ[] tp = new PointPrecompZ[count];
            Init(out PointTemp t);
            PointPrecomputeZ(ref p, tp, count, ref t);

            PointSetNeutral(ref r);

            for (int bit = 252;;)
            {
                int wp = ws_p[bit];
                if (wp != 0)
                {
                    int index = (wp >> 1) ^ (wp >> 31);
                    PointAddVar(wp < 0, ref tp[index], ref r, ref t);
                }

                if (--bit < 0)
                    break;

                PointDouble(ref r);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ScalarMultStraus128Var(ReadOnlySpan<uint> nb, ReadOnlySpan<uint> np, ref PointAffine p,
            ReadOnlySpan<uint> nq, ref PointAffine q, ref PointAccum r)
#else
        private static void ScalarMultStraus128Var(uint[] nb, uint[] np, ref PointAffine p, uint[] nq,
            ref PointAffine q, ref PointAccum r)
#endif
        {
            Debug.Assert(nb.Length == ScalarUints);
            Debug.Assert(nb[ScalarUints - 1] >> 29 == 0U);
            Debug.Assert(np.Length == 4);
            Debug.Assert(nq.Length == 4);

            Precompute();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<sbyte> ws_b = stackalloc sbyte[256];
            Span<sbyte> ws_p = stackalloc sbyte[128];
            Span<sbyte> ws_q = stackalloc sbyte[128];
#else
            sbyte[] ws_b = new sbyte[256];
            sbyte[] ws_p = new sbyte[128];
            sbyte[] ws_q = new sbyte[128];
#endif

            Wnaf.GetSignedVar(nb, WnafWidthBase, ws_b);
            Wnaf.GetSignedVar(np, WnafWidth128, ws_p);
            Wnaf.GetSignedVar(nq, WnafWidth128, ws_q);

            int count = 1 << (WnafWidth128 - 2);
            PointPrecompZ[] tp = new PointPrecompZ[count];
            PointPrecompZ[] tq = new PointPrecompZ[count];
            Init(out PointTemp t);
            PointPrecomputeZ(ref p, tp, count, ref t);
            PointPrecomputeZ(ref q, tq, count, ref t);

            PointSetNeutral(ref r);

            int bit = 128;
            while (--bit >= 0)
            {
                int wb = ws_b[bit];
                if (wb != 0)
                {
                    int index = (wb >> 1) ^ (wb >> 31);
                    PointAddVar(wb < 0, ref PrecompBaseWnaf[index], ref r, ref t);
                }

                int wb128 = ws_b[128 + bit];
                if (wb128 != 0)
                {
                    int index = (wb128 >> 1) ^ (wb128 >> 31);
                    PointAddVar(wb128 < 0, ref PrecompBase128Wnaf[index], ref r, ref t);
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

                PointDouble(ref r);
            }

            // NOTE: Together with the final PointDouble of the loop, this clears the cofactor of 8
            PointDouble(ref r);
            PointDouble(ref r);
        }

        public static void Sign(byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            byte[] ctx = null;
            byte phflag = 0x00;

            ImplSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        public static void Sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig,
            int sigOff)
        {
            byte[] ctx = null;
            byte phflag = 0x00;

            ImplSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
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

        public static void SignPrehash(byte[] sk, int skOff, byte[] ctx, IDigest ph, byte[] sig, int sigOff)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.DoFinal(m, 0))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            ImplSign(sk, skOff, ctx, phflag, m, 0, m.Length, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, IDigest ph, byte[] sig,
            int sigOff)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.DoFinal(m, 0))
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

        public static bool Verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)
        {
            byte[] ctx = null;
            byte phflag = 0x00;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
        }

        public static bool Verify(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] m, int mOff, int mLen)
        {
            byte[] ctx = null;
            byte phflag = 0x00;

            return ImplVerify(sig, sigOff, publicPoint, ctx, phflag, m, mOff, mLen);
        }

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

        public static bool VerifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, IDigest ph)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.DoFinal(m, 0))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, 0, m.Length);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, PublicPoint publicPoint, byte[] ctx, IDigest ph)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.DoFinal(m, 0))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, publicPoint, ctx, phflag, m, 0, m.Length);
        }
    }
}
