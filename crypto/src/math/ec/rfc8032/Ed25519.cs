using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    public abstract class Ed25519
    {
        // -x^2 + y^2 == 1 + 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3 * x^2 * y^2

        public enum Algorithm
        {
            Ed25519 = 0,
            Ed25519ctx = 1,
            Ed25519ph = 2,
        }

        private class F : X25519Field {};

        private const long M08L = 0x000000FFL;
        private const long M28L = 0x0FFFFFFFL;
        private const long M32L = 0xFFFFFFFFL;

        private const int CoordUints = 8;
        private const int PointBytes = CoordUints * 4;
        private const int ScalarUints = 8;
        private const int ScalarBytes = ScalarUints * 4;

        public static readonly int PrehashSize = 64;
        public static readonly int PublicKeySize = PointBytes;
        public static readonly int SecretKeySize = 32;
        public static readonly int SignatureSize = PointBytes + ScalarBytes;

        // "SigEd25519 no Ed25519 collisions"
        private static readonly byte[] Dom2Prefix = new byte[]{ 0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
            0x39, 0x20, 0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69,
            0x73, 0x69, 0x6f, 0x6e, 0x73 };

        private static readonly uint[] P = { 0xFFFFFFEDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
            0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU };
        private static readonly uint[] L = { 0x5CF5D3EDU, 0x5812631AU, 0xA2F79CD6U, 0x14DEF9DEU, 0x00000000U,
            0x00000000U, 0x00000000U, 0x10000000U };

        private const int L0 = unchecked((int)0xFCF5D3ED);  // L0:26/--
        private const int L1 =                0x012631A6;   // L1:24/22
        private const int L2 =                0x079CD658;   // L2:27/--
        private const int L3 = unchecked((int)0xFF9DEA2F);  // L3:23/--
        private const int L4 =                0x000014DF;   // L4:12/11

        private static readonly int[] B_x = { 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
            0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };
        private static readonly int[] B_y = { 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
            0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };
        private static readonly int[] C_d = { 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898,
            0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
        private static readonly int[] C_d2 = { 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130,
            0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };
        private static readonly int[] C_d4 = { 0x0165E2B2, 0x034DCA13, 0x002ADD7A, 0x01A8283B, 0x00038052, 0x01E7A260,
            0x03407977, 0x019CE331, 0x01C56DFF, 0x00901B67 };

        private const int WnafWidthBase = 7;

        private const int PrecompBlocks = 8;
        private const int PrecompTeeth = 4;
        private const int PrecompSpacing = 8;
        private const int PrecompPoints = 1 << (PrecompTeeth - 1);
        private const int PrecompMask = PrecompPoints - 1;

        private static readonly object precompLock = new object();
        // TODO[ed25519] Convert to PointPrecomp
        private static PointExt[] precompBaseTable = null;
        private static int[] precompBase = null;

        private class PointAccum
        {
            internal int[] x = F.Create();
            internal int[] y = F.Create();
            internal int[] z = F.Create();
            internal int[] u = F.Create();
            internal int[] v = F.Create();
        }

        private class PointAffine
        {
            internal int[] x = F.Create();
            internal int[] y = F.Create();
        }

        private class PointExt
        {
            internal int[] x = F.Create();
            internal int[] y = F.Create();
            internal int[] z = F.Create();
            internal int[] t = F.Create();
        }

        private class PointPrecomp
        {
            internal int[] ypx_h = F.Create();
            internal int[] ymx_h = F.Create();
            internal int[] xyd = F.Create();
        }

        private static byte[] CalculateS(byte[] r, byte[] k, byte[] s)
        {
            uint[] t = new uint[ScalarUints * 2];   DecodeScalar(r, 0, t);
            uint[] u = new uint[ScalarUints];       DecodeScalar(k, 0, u);
            uint[] v = new uint[ScalarUints];       DecodeScalar(s, 0, v);

            Nat256.MulAddTo(u, v, t);

            byte[] result = new byte[ScalarBytes * 2];
            for (int i = 0; i < t.Length; ++i)
            {
                Encode32(t[i], result, i * 4);
            }
            return ReduceScalar(result);
        }

        private static bool CheckContextVar(byte[] ctx, byte phflag)
        {
            return ctx == null && phflag == 0x00
                || ctx != null && ctx.Length < 256;
        }

        private static int CheckPoint(int[] x, int[] y)
        {
            int[] t = F.Create();
            int[] u = F.Create();
            int[] v = F.Create();

            F.Sqr(x, u);
            F.Sqr(y, v);
            F.Mul(u, v, t);
            F.Sub(v, u, v);
            F.Mul(t, C_d, t);
            F.AddOne(t);
            F.Sub(t, v, t);
            F.Normalize(t);

            return F.IsZero(t);
        }

        private static int CheckPoint(int[] x, int[] y, int[] z)
        {
            int[] t = F.Create();
            int[] u = F.Create();
            int[] v = F.Create();
            int[] w = F.Create();

            F.Sqr(x, u);
            F.Sqr(y, v);
            F.Sqr(z, w);
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

        private static bool CheckPointVar(byte[] p)
        {
            uint[] t = new uint[CoordUints];
            Decode32(p, 0, t, 0, CoordUints);
            t[CoordUints - 1] &= 0x7FFFFFFFU;
            return !Nat256.Gte(t, P);
        }

        private static bool CheckScalarVar(byte[] s, uint[] n)
        {
            DecodeScalar(s, 0, n);
            return !Nat256.Gte(n, L);
        }

        private static byte[] Copy(byte[] buf, int off, int len)
        {
            byte[] result = new byte[len];
            Array.Copy(buf, off, result, 0, len);
            return result;
        }

        private static IDigest CreateDigest()
        {
            return new Sha512Digest();
        }

        public static IDigest CreatePrehash()
        {
            return CreateDigest();
        }

        private static uint Decode24(byte[] bs, int off)
        {
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off] << 16;
            return n;
        }

        private static uint Decode32(byte[] bs, int off)
        {
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 24;
            return n;
        }

        private static void Decode32(byte[] bs, int bsOff, uint[] n, int nOff, int nLen)
        {
            for (int i = 0; i < nLen; ++i)
            {
                n[nOff + i] = Decode32(bs, bsOff + i * 4);
            }
        }

        private static bool DecodePointVar(byte[] p, int pOff, bool negate, PointAffine r)
        {
            byte[] py = Copy(p, pOff, PointBytes);
            if (!CheckPointVar(py))
                return false;

            int x_0 = (py[PointBytes - 1] & 0x80) >> 7;
            py[PointBytes - 1] &= 0x7F;

            F.Decode(py, 0, r.y);

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
            }

            return true;
        }

        private static void DecodeScalar(byte[] k, int kOff, uint[] n)
        {
            Decode32(k, kOff, n, 0, ScalarUints);
        }

        private static void Dom2(IDigest d, byte phflag, byte[] ctx)
        {
            if (ctx != null)
            {
                int n = Dom2Prefix.Length;
                byte[] t = new byte[n + 2 + ctx.Length];
                Dom2Prefix.CopyTo(t, 0);
                t[n] = phflag;
                t[n + 1] = (byte)ctx.Length;
                ctx.CopyTo(t, n + 2);

                d.BlockUpdate(t, 0, t.Length);
            }
        }

        private static void Encode24(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n >> 16);
        }

        private static void Encode32(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 24);
        }

        private static void Encode56(ulong n, byte[] bs, int off)
        {
            Encode32((uint)n, bs, off);
            Encode24((uint)(n >> 32), bs, off + 4);
        }

        private static int EncodePoint(PointAccum p, byte[] r, int rOff)
        {
            int[] x = F.Create();
            int[] y = F.Create();

            F.Inv(p.z, y);
            F.Mul(p.x, y, x);
            F.Mul(p.y, y, y);
            F.Normalize(x);
            F.Normalize(y);

            int result = CheckPoint(x, y);

            F.Encode(y, r, rOff);
            r[rOff + PointBytes - 1] |= (byte)((x[0] & 1) << 7);

            return result;
        }

        public static void GeneratePrivateKey(SecureRandom random, byte[] k)
        {
            random.NextBytes(k);
        }

        public static void GeneratePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff)
        {
            IDigest d = CreateDigest();
            byte[] h = new byte[d.GetDigestSize()];

            d.BlockUpdate(sk, skOff, SecretKeySize);
            d.DoFinal(h, 0);

            byte[] s = new byte[ScalarBytes];
            PruneScalar(h, 0, s);

            ScalarMultBaseEncoded(s, pk, pkOff);
        }

        private static uint GetWindow4(uint[] x, int n)
        {
            int w = (int)((uint)n >> 3), b = (n & 7) << 2;
            return (x[w] >> b) & 15U;
        }

        private static sbyte[] GetWnafVar(uint[] n, int width)
        {
            Debug.Assert(n[ScalarUints - 1] <= L[ScalarUints - 1]);
            Debug.Assert(2 <= width && width <= 8);

            uint[] t = new uint[ScalarUints * 2];
            {
                uint c = 0;
                int tPos = t.Length, i = ScalarUints;
                while (--i >= 0)
                {
                    uint next = n[i];
                    t[--tPos] = (next >> 16) | (c << 16);
                    t[--tPos] = c = next;
                }
            }

            sbyte[] ws = new sbyte[253];

            int lead = 32 - width;

            uint carry = 0U;
            int j = 0;
            for (int i = 0; i < t.Length; ++i, j -= 16)
            {
                uint word = t[i];
                while (j < 16)
                {
                    uint word16 = word >> j;
                    uint bit = word16 & 1U;

                    if (bit == carry)
                    {
                        ++j;
                        continue;
                    }

                    uint digit = (word16 | 1U) << lead;
                    carry = digit >> 31;

                    ws[(i << 4) + j] = (sbyte)((int)digit >> lead);

                    j += width;
                }
            }

            Debug.Assert(carry == 0);

            return ws;
        }

        private static void ImplSign(IDigest d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag,
            byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            Dom2(d, phflag, ctx);
            d.BlockUpdate(h, ScalarBytes, ScalarBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] r = ReduceScalar(h);
            byte[] R = new byte[PointBytes];
            ScalarMultBaseEncoded(r, R, 0);

            Dom2(d, phflag, ctx);
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(pk, pkOff, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] k = ReduceScalar(h);
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
            byte[] h = new byte[d.GetDigestSize()];

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
            byte[] h = new byte[d.GetDigestSize()];

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

            byte[] R = Copy(sig, sigOff, PointBytes);
            byte[] S = Copy(sig, sigOff + PointBytes, ScalarBytes);

            if (!CheckPointVar(R))
                return false;

            uint[] nS = new uint[ScalarUints];
            if (!CheckScalarVar(S, nS))
                return false;

            PointAffine pA = new PointAffine();
            if (!DecodePointVar(pk, pkOff, true, pA))
                return false;

            IDigest d = CreateDigest();
            byte[] h = new byte[d.GetDigestSize()];

            Dom2(d, phflag, ctx);
            d.BlockUpdate(R, 0, PointBytes);
            d.BlockUpdate(pk, pkOff, PointBytes);
            d.BlockUpdate(m, mOff, mLen);
            d.DoFinal(h, 0);

            byte[] k = ReduceScalar(h);

            uint[] nA = new uint[ScalarUints];
            DecodeScalar(k, 0, nA);

            PointAccum pR = new PointAccum();
            ScalarMultStrausVar(nS, nA, pA, pR);

            byte[] check = new byte[PointBytes];
            return 0 != EncodePoint(pR, check, 0) && Arrays.AreEqual(check, R);
        }

        private static bool IsNeutralElementVar(int[] x, int[] y)
        {
            return F.IsZeroVar(x) && F.IsOneVar(y);
        }

        private static bool IsNeutralElementVar(int[] x, int[] y, int[] z)
        {
            return F.IsZeroVar(x) && F.AreEqualVar(y, z);
        }

        private static void PointAdd(PointExt p, PointAccum r)
        {
            int[] a = F.Create();
            int[] b = F.Create();
            int[] c = F.Create();
            int[] d = F.Create();
            int[] e = r.u;
            int[] f = F.Create();
            int[] g = F.Create();
            int[] h = r.v;

            F.Apm(r.y, r.x, b, a);
            F.Apm(p.y, p.x, d, c);
            F.Mul(a, c, a);
            F.Mul(b, d, b);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.t, c);
            F.Mul(c, C_d2, c);
            F.Mul(r.z, p.z, d);
            F.Add(d, d, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, g, f);
            F.Carry(g);
            F.Mul(e, f, r.x);
            F.Mul(g, h, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointAdd(PointExt p, PointExt r)
        {
            int[] a = F.Create();
            int[] b = F.Create();
            int[] c = F.Create();
            int[] d = F.Create();
            int[] e = F.Create();
            int[] f = F.Create();
            int[] g = F.Create();
            int[] h = F.Create();

            F.Apm(p.y, p.x, b, a);
            F.Apm(r.y, r.x, d, c);
            F.Mul(a, c, a);
            F.Mul(b, d, b);
            F.Mul(p.t, r.t, c);
            F.Mul(c, C_d2, c);
            F.Mul(p.z, r.z, d);
            F.Add(d, d, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, g, f);
            F.Carry(g);
            F.Mul(e, f, r.x);
            F.Mul(g, h, r.y);
            F.Mul(f, g, r.z);
            F.Mul(e, h, r.t);
        }

        private static void PointAddVar(bool negate, PointExt p, PointAccum r)
        {
            int[] a = F.Create();
            int[] b = F.Create();
            int[] c = F.Create();
            int[] d = F.Create();
            int[] e = r.u;
            int[] f = F.Create();
            int[] g = F.Create();
            int[] h = r.v;

            int[] nc, nd, nf, ng;
            if (negate)
            {
                nc = d; nd = c; nf = g; ng = f;
            }
            else
            {
                nc = c; nd = d; nf = f; ng = g;
            }

            F.Apm(r.y, r.x, b, a);
            F.Apm(p.y, p.x, nd, nc);
            F.Mul(a, c, a);
            F.Mul(b, d, b);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.t, c);
            F.Mul(c, C_d2, c);
            F.Mul(r.z, p.z, d);
            F.Add(d, d, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, ng, nf);
            F.Carry(ng);
            F.Mul(e, f, r.x);
            F.Mul(g, h, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointAddVar(bool negate, PointExt p, PointExt q, PointExt r)
        {
            int[] a = F.Create();
            int[] b = F.Create();
            int[] c = F.Create();
            int[] d = F.Create();
            int[] e = F.Create();
            int[] f = F.Create();
            int[] g = F.Create();
            int[] h = F.Create();

            int[] nc, nd, nf, ng;
            if (negate)
            {
                nc = d; nd = c; nf = g; ng = f;
            }
            else
            {
                nc = c; nd = d; nf = f; ng = g;
            }

            F.Apm(p.y, p.x, b, a);
            F.Apm(q.y, q.x, nd, nc);
            F.Mul(a, c, a);
            F.Mul(b, d, b);
            F.Mul(p.t, q.t, c);
            F.Mul(c, C_d2, c);
            F.Mul(p.z, q.z, d);
            F.Add(d, d, d);
            F.Apm(b, a, h, e);
            F.Apm(d, c, ng, nf);
            F.Carry(ng);
            F.Mul(e, f, r.x);
            F.Mul(g, h, r.y);
            F.Mul(f, g, r.z);
            F.Mul(e, h, r.t);
        }

        private static void PointAddPrecomp(PointPrecomp p, PointAccum r)
        {
            int[] a = F.Create();
            int[] b = F.Create();
            int[] c = F.Create();
            int[] e = r.u;
            int[] f = F.Create();
            int[] g = F.Create();
            int[] h = r.v;

            F.Apm(r.y, r.x, b, a);
            F.Mul(a, p.ymx_h, a);
            F.Mul(b, p.ypx_h, b);
            F.Mul(r.u, r.v, c);
            F.Mul(c, p.xyd, c);
            F.Apm(b, a, h, e);
            F.Apm(r.z, c, g, f);
            F.Carry(g);
            F.Mul(e, f, r.x);
            F.Mul(g, h, r.y);
            F.Mul(f, g, r.z);
        }

        private static PointExt PointCopy(PointAccum p)
        {
            PointExt r = new PointExt();
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            F.Copy(p.z, 0, r.z, 0);
            F.Mul(p.u, p.v, r.t);
            return r;
        }

        private static PointExt PointCopy(PointAffine p)
        {
            PointExt r = new PointExt();
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            PointExtendXY(r);
            return r;
        }

        private static PointExt PointCopy(PointExt p)
        {
            PointExt r = new PointExt();
            PointCopy(p, r);
            return r;
        }

        private static void PointCopy(PointAffine p, PointAccum r)
        {
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            PointExtendXY(r);
        }

        private static void PointCopy(PointExt p, PointExt r)
        {
            F.Copy(p.x, 0, r.x, 0);
            F.Copy(p.y, 0, r.y, 0);
            F.Copy(p.z, 0, r.z, 0);
            F.Copy(p.t, 0, r.t, 0);
        }

        private static void PointDouble(PointAccum r)
        {
            int[] a = F.Create();
            int[] b = F.Create();
            int[] c = F.Create();
            int[] e = r.u;
            int[] f = F.Create();
            int[] g = F.Create();
            int[] h = r.v;

            F.Sqr(r.x, a);
            F.Sqr(r.y, b);
            F.Sqr(r.z, c);
            F.Add(c, c, c);
            F.Apm(a, b, h, g);
            F.Add(r.x, r.y, e);
            F.Sqr(e, e);
            F.Sub(h, e, e);
            F.Add(c, g, f);
            F.Carry(f);
            F.Mul(e, f, r.x);
            F.Mul(g, h, r.y);
            F.Mul(f, g, r.z);
        }

        private static void PointExtendXY(PointAccum p)
        {
            F.One(p.z);
            F.Copy(p.x, 0, p.u, 0);
            F.Copy(p.y, 0, p.v, 0);
        }

        private static void PointExtendXY(PointExt p)
        {
            F.One(p.z);
            F.Mul(p.x, p.y, p.t);
        }

        private static void PointLookup(int block, int index, PointPrecomp p)
        {
            Debug.Assert(0 <= block && block < PrecompBlocks);
            Debug.Assert(0 <= index && index < PrecompPoints);

            int off = block * PrecompPoints * 3 * F.Size;

            for (int i = 0; i < PrecompPoints; ++i)
            {
                int cond = ((i ^ index) - 1) >> 31;
                F.CMov(cond, precompBase, off, p.ypx_h, 0);     off += F.Size;
                F.CMov(cond, precompBase, off, p.ymx_h, 0);     off += F.Size;
                F.CMov(cond, precompBase, off, p.xyd, 0);       off += F.Size;
            }
        }

        private static void PointLookup(uint[] x, int n, int[] table, PointExt r)
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
                F.CMov(cond, table, off, r.t, 0);       off += F.Size;
            }

            F.CNegate(sign, r.x);
            F.CNegate(sign, r.t);
        }

        private static void PointLookup(int[] table, int index, PointExt r)
        {
            int off = F.Size * 4 * index;

            F.Copy(table, off, r.x, 0);     off += F.Size;
            F.Copy(table, off, r.y, 0);     off += F.Size;
            F.Copy(table, off, r.z, 0);     off += F.Size;
            F.Copy(table, off, r.t, 0);
        }

        private static int[] PointPrecompute(PointAffine p, int count)
        {
            Debug.Assert(count > 0);

            PointExt q = PointCopy(p);
            PointExt d = PointCopy(q);
            PointAdd(q, d);

            int[] table = F.CreateTable(count * 4);
            int off = 0;

            int i = 0;
            for (;;)
            {
                F.Copy(q.x, 0, table, off); off += F.Size;
                F.Copy(q.y, 0, table, off); off += F.Size;
                F.Copy(q.z, 0, table, off); off += F.Size;
                F.Copy(q.t, 0, table, off); off += F.Size;

                if (++i == count)
                    break;

                PointAdd(d, q);
            }

            return table;
        }

        private static PointExt[] PointPrecomputeVar(PointExt p, int count)
        {
            Debug.Assert(count > 0);

            PointExt d = new PointExt();
            PointAddVar(false, p, p, d);

            PointExt[] table = new PointExt[count];
            table[0] = PointCopy(p);
            for (int i = 1; i < count; ++i)
            {
                PointAddVar(false, table[i - 1], d, table[i] = new PointExt());
            }
            return table;
        }

        private static void PointSetNeutral(PointAccum p)
        {
            F.Zero(p.x);
            F.One(p.y);
            F.One(p.z);
            F.Zero(p.u);
            F.One(p.v);
        }

        private static void PointSetNeutral(PointExt p)
        {
            F.Zero(p.x);
            F.One(p.y);
            F.One(p.z);
            F.Zero(p.t);
        }

        public static void Precompute()
        {
            lock (precompLock)
            {
                if (precompBase != null)
                    return;

                // Precomputed table for the base point in verification ladder
                {
                    PointExt b = new PointExt();
                    F.Copy(B_x, 0, b.x, 0);
                    F.Copy(B_y, 0, b.y, 0);
                    PointExtendXY(b);

                    precompBaseTable = PointPrecomputeVar(b, 1 << (WnafWidthBase - 2));
                }

                PointAccum p = new PointAccum();
                F.Copy(B_x, 0, p.x, 0);
                F.Copy(B_y, 0, p.y, 0);
                PointExtendXY(p);

                precompBase = F.CreateTable(PrecompBlocks * PrecompPoints * 3);

                int off = 0;
                for (int b = 0; b < PrecompBlocks; ++b)
                {
                    PointExt[] ds = new PointExt[PrecompTeeth];

                    PointExt sum = new PointExt();
                    PointSetNeutral(sum);

                    for (int t = 0; t < PrecompTeeth; ++t)
                    {
                        PointExt q = PointCopy(p);
                        PointAddVar(true, sum, q, sum);
                        PointDouble(p);

                        ds[t] = PointCopy(p);

                        if (b + t != PrecompBlocks + PrecompTeeth - 2)
                        {
                            for (int s = 1; s < PrecompSpacing; ++s)
                            {
                                PointDouble(p);
                            }
                        }
                    }

                    PointExt[] points = new PointExt[PrecompPoints];
                    int k = 0;
                    points[k++] = sum;

                    for (int t = 0; t < (PrecompTeeth - 1); ++t)
                    {
                        int size = 1 << t;
                        for (int j = 0; j < size; ++j, ++k)
                        {
                            PointAddVar(false, points[k - size], ds[t], points[k] = new PointExt());
                        }
                    }

                    Debug.Assert(k == PrecompPoints);

                    int[] cs = F.CreateTable(PrecompPoints);

                    // TODO[ed25519] A single batch inversion across all blocks?
                    {
                        int[] u = F.Create();
                        F.Copy(points[0].z, 0, u, 0);
                        F.Copy(u, 0, cs, 0);

                        int i = 0;
                        while (++i < PrecompPoints)
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
                            F.Copy(t, 0, cs, j * F.Size);
                            F.Mul(u, points[j].z, u);
                        }

                        F.Copy(u, 0, cs, 0);
                    }

                    for (int i = 0; i < PrecompPoints; ++i)
                    {
                        PointExt q = points[i];

                        int[] x = F.Create();
                        int[] y = F.Create();

                        //F.Add(q.z, q.z, x);
                        //F.InvVar(x, y);
                        F.Copy(cs, i * F.Size, y, 0);

                        F.Mul(q.x, y, x);
                        F.Mul(q.y, y, y);

                        PointPrecomp r = new PointPrecomp();
                        F.Apm(y, x, r.ypx_h, r.ymx_h);
                        F.Mul(x, y, r.xyd);
                        F.Mul(r.xyd, C_d4, r.xyd);

                        F.Normalize(r.ypx_h);
                        F.Normalize(r.ymx_h);
                        //F.Normalize(r.xyd);

                        F.Copy(r.ypx_h, 0, precompBase, off);       off += F.Size;
                        F.Copy(r.ymx_h, 0, precompBase, off);       off += F.Size;
                        F.Copy(r.xyd, 0, precompBase, off);         off += F.Size;
                    }
                }

                Debug.Assert(off == precompBase.Length);
            }
        }

        private static void PruneScalar(byte[] n, int nOff, byte[] r)
        {
            Array.Copy(n, nOff, r, 0, ScalarBytes);

            r[0] &= 0xF8;
            r[ScalarBytes - 1] &= 0x7F;
            r[ScalarBytes - 1] |= 0x40;
        }

        private static byte[] ReduceScalar(byte[] n)
        {
            long x00 = Decode32(n,  0) & M32L;          // x00:32/--
            long x01 = (Decode24(n, 4) << 4) & M32L;    // x01:28/--
            long x02 = Decode32(n,  7) & M32L;          // x02:32/--
            long x03 = (Decode24(n, 11) << 4) & M32L;   // x03:28/--
            long x04 = Decode32(n, 14) & M32L;          // x04:32/--
            long x05 = (Decode24(n, 18) << 4) & M32L;   // x05:28/--
            long x06 = Decode32(n, 21) & M32L;          // x06:32/--
            long x07 = (Decode24(n, 25) << 4) & M32L;   // x07:28/--
            long x08 = Decode32(n, 28) & M32L;          // x08:32/--
            long x09 = (Decode24(n, 32) << 4) & M32L;   // x09:28/--
            long x10 = Decode32(n, 35) & M32L;          // x10:32/--
            long x11 = (Decode24(n, 39) << 4) & M32L;   // x11:28/--
            long x12 = Decode32(n, 42) & M32L;          // x12:32/--
            long x13 = (Decode24(n, 46) << 4) & M32L;   // x13:28/--
            long x14 = Decode32(n, 49) & M32L;          // x14:32/--
            long x15 = (Decode24(n, 53) << 4) & M32L;   // x15:28/--
            long x16 = Decode32(n, 56) & M32L;          // x16:32/--
            long x17 = (Decode24(n, 60) << 4) & M32L;   // x17:28/--
            long x18 = n[63]                  & M08L;   // x18:08/--
            long t;

            //x18 += (x17 >> 28); x17 &= M28L;
            x09 -= x18 * L0;                            // x09:34/28
            x10 -= x18 * L1;                            // x10:33/30
            x11 -= x18 * L2;                            // x11:35/28
            x12 -= x18 * L3;                            // x12:32/31
            x13 -= x18 * L4;                            // x13:28/21

            x17 += (x16 >> 28); x16 &= M28L;            // x17:28/--, x16:28/--
            x08 -= x17 * L0;                            // x08:54/32
            x09 -= x17 * L1;                            // x09:52/51
            x10 -= x17 * L2;                            // x10:55/34
            x11 -= x17 * L3;                            // x11:51/36
            x12 -= x17 * L4;                            // x12:41/--

            //x16 += (x15 >> 28); x15 &= M28L;
            x07 -= x16 * L0;                            // x07:54/28
            x08 -= x16 * L1;                            // x08:54/53
            x09 -= x16 * L2;                            // x09:55/53
            x10 -= x16 * L3;                            // x10:55/52
            x11 -= x16 * L4;                            // x11:51/41

            x15 += (x14 >> 28); x14 &= M28L;            // x15:28/--, x14:28/--
            x06 -= x15 * L0;                            // x06:54/32
            x07 -= x15 * L1;                            // x07:54/53
            x08 -= x15 * L2;                            // x08:56/--
            x09 -= x15 * L3;                            // x09:55/54
            x10 -= x15 * L4;                            // x10:55/53

            //x14 += (x13 >> 28); x13 &= M28L;
            x05 -= x14 * L0;                            // x05:54/28
            x06 -= x14 * L1;                            // x06:54/53
            x07 -= x14 * L2;                            // x07:56/--
            x08 -= x14 * L3;                            // x08:56/51
            x09 -= x14 * L4;                            // x09:56/--

            x13 += (x12 >> 28); x12 &= M28L;            // x13:28/22, x12:28/--
            x04 -= x13 * L0;                            // x04:54/49
            x05 -= x13 * L1;                            // x05:54/53
            x06 -= x13 * L2;                            // x06:56/--
            x07 -= x13 * L3;                            // x07:56/52
            x08 -= x13 * L4;                            // x08:56/52

            x12 += (x11 >> 28); x11 &= M28L;            // x12:28/24, x11:28/--
            x03 -= x12 * L0;                            // x03:54/49
            x04 -= x12 * L1;                            // x04:54/51
            x05 -= x12 * L2;                            // x05:56/--
            x06 -= x12 * L3;                            // x06:56/52
            x07 -= x12 * L4;                            // x07:56/53

            x11 += (x10 >> 28); x10 &= M28L;            // x11:29/--, x10:28/--
            x02 -= x11 * L0;                            // x02:55/32
            x03 -= x11 * L1;                            // x03:55/--
            x04 -= x11 * L2;                            // x04:56/55
            x05 -= x11 * L3;                            // x05:56/52
            x06 -= x11 * L4;                            // x06:56/53

            x10 += (x09 >> 28); x09 &= M28L;            // x10:29/--, x09:28/--
            x01 -= x10 * L0;                            // x01:55/28
            x02 -= x10 * L1;                            // x02:55/54
            x03 -= x10 * L2;                            // x03:56/55
            x04 -= x10 * L3;                            // x04:57/--
            x05 -= x10 * L4;                            // x05:56/53

            x08 += (x07 >> 28); x07 &= M28L;            // x08:56/53, x07:28/--
            x09 += (x08 >> 28); x08 &= M28L;            // x09:29/25, x08:28/--

            t    = (x08 >> 27) & 1L;
            x09 += t;                                   // x09:29/26

            x00 -= x09 * L0;                            // x00:55/53
            x01 -= x09 * L1;                            // x01:55/54
            x02 -= x09 * L2;                            // x02:57/--
            x03 -= x09 * L3;                            // x03:57/--
            x04 -= x09 * L4;                            // x04:57/42

            x01 += (x00 >> 28); x00 &= M28L;
            x02 += (x01 >> 28); x01 &= M28L;
            x03 += (x02 >> 28); x02 &= M28L;
            x04 += (x03 >> 28); x03 &= M28L;
            x05 += (x04 >> 28); x04 &= M28L;
            x06 += (x05 >> 28); x05 &= M28L;
            x07 += (x06 >> 28); x06 &= M28L;
            x08 += (x07 >> 28); x07 &= M28L;
            x09  = (x08 >> 28); x08 &= M28L;

            x09 -= t;

            Debug.Assert(x09 == 0L || x09 == -1L);

            x00 += x09 & L0;
            x01 += x09 & L1;
            x02 += x09 & L2;
            x03 += x09 & L3;
            x04 += x09 & L4;

            x01 += (x00 >> 28); x00 &= M28L;
            x02 += (x01 >> 28); x01 &= M28L;
            x03 += (x02 >> 28); x02 &= M28L;
            x04 += (x03 >> 28); x03 &= M28L;
            x05 += (x04 >> 28); x04 &= M28L;
            x06 += (x05 >> 28); x05 &= M28L;
            x07 += (x06 >> 28); x06 &= M28L;
            x08 += (x07 >> 28); x07 &= M28L;

            byte[] r = new byte[ScalarBytes];
            Encode56((ulong)(x00 | (x01 << 28)), r, 0);
            Encode56((ulong)(x02 | (x03 << 28)), r, 7);
            Encode56((ulong)(x04 | (x05 << 28)), r, 14);
            Encode56((ulong)(x06 | (x07 << 28)), r, 21);
            Encode32((uint)x08, r, 28);
            return r;
        }

        private static void ScalarMult(byte[] k, PointAffine p, PointAccum r)
        {
            uint[] n = new uint[ScalarUints];
            DecodeScalar(k, 0, n);

            Debug.Assert(0U == (n[0] & 7));
            Debug.Assert(1U == n[ScalarUints - 1] >> 30);

            Nat.ShiftDownBits(ScalarUints, n, 3, 1U);

            // Recode the scalar into signed-digit form
            {
                uint c1 = Nat.CAdd(ScalarUints, ~(int)n[0] & 1, n, L, n);   Debug.Assert(c1 == 0U);
                uint c2 = Nat.ShiftDownBit(ScalarUints, n, 0U);             Debug.Assert(c2 == (1U << 31));
            }

            Debug.Assert(1U == n[ScalarUints - 1] >> 28);

            int[] table = PointPrecompute(p, 8);
            PointExt q = new PointExt();

            // Replace first 4 doublings (2^4 * P) with 1 addition (P + 15 * P)
            PointCopy(p, r);
            PointLookup(table, 7, q);
            PointAdd(q, r);

            int w = 62;
            for (;;)
            {
                PointLookup(n, w, table, q);
                PointAdd(q, r);

                PointDouble(r);
                PointDouble(r);
                PointDouble(r);

                if (--w < 0)
                    break;

                PointDouble(r);
            }
        }

        private static void ScalarMultBase(byte[] k, PointAccum r)
        {
            Precompute();

            uint[] n = new uint[ScalarUints];
            DecodeScalar(k, 0, n);

            // Recode the scalar into signed-digit form, then group comb bits in each block
            {
                uint c1 = Nat.CAdd(ScalarUints, ~(int)n[0] & 1, n, L, n);   Debug.Assert(c1 == 0U);
                uint c2 = Nat.ShiftDownBit(ScalarUints, n, 1U);             Debug.Assert(c2 == (1U << 31));

                for (int i = 0; i < ScalarUints; ++i)
                {
                    n[i] = Interleave.Shuffle2(n[i]);
                }
            }

            PointPrecomp p = new PointPrecomp();

            PointSetNeutral(r);

            int cOff = (PrecompSpacing - 1) * PrecompTeeth;
            for (;;)
            {
                for (int b = 0; b < PrecompBlocks; ++b)
                {
                    uint w = n[b] >> cOff;
                    int sign = (int)(w >> (PrecompTeeth - 1)) & 1;
                    int abs = ((int)w ^ -sign) & PrecompMask;

                    Debug.Assert(sign == 0 || sign == 1);
                    Debug.Assert(0 <= abs && abs < PrecompPoints);

                    PointLookup(b, abs, p);

                    F.CSwap(sign, p.ypx_h, p.ymx_h);
                    F.CNegate(sign, p.xyd);

                    PointAddPrecomp(p, r);
                }

                if ((cOff -= PrecompTeeth) < 0)
                    break;

                PointDouble(r);
            }
        }

        private static void ScalarMultBaseEncoded(byte[] k, byte[] r, int rOff)
        {
            PointAccum p = new PointAccum();
            ScalarMultBase(k, p);
            if (0 == EncodePoint(p, r, rOff))
                throw new InvalidOperationException();
        }

        internal static void ScalarMultBaseYZ(byte[] k, int kOff, int[] y, int[] z)
        {
            byte[] n = new byte[ScalarBytes];
            PruneScalar(k, kOff, n);

            PointAccum p = new PointAccum();
            ScalarMultBase(n, p);

            if (0 == CheckPoint(p.x, p.y, p.z))
                throw new InvalidOperationException();

            F.Copy(p.y, 0, y, 0);
            F.Copy(p.z, 0, z, 0);
        }

        private static void ScalarMultOrderVar(PointAffine p, PointAccum r)
        {
            int width = 5;

            sbyte[] ws_p = GetWnafVar(L, width);

            PointExt[] tp = PointPrecomputeVar(PointCopy(p), 1 << (width - 2));

            PointSetNeutral(r);

            for (int bit = 252; ;)
            {
                int wp = ws_p[bit];
                if (wp != 0)
                {
                    int sign = wp >> 31;
                    int index = (wp ^ sign) >> 1;

                    PointAddVar((sign != 0), tp[index], r);
                }

                if (--bit < 0)
                    break;

                PointDouble(r);
            }
        }

        private static void ScalarMultStrausVar(uint[] nb, uint[] np, PointAffine p, PointAccum r)
        {
            Precompute();

            int width = 5;

            sbyte[] ws_b = GetWnafVar(nb, WnafWidthBase);
            sbyte[] ws_p = GetWnafVar(np, width);

            PointExt[] tp = PointPrecomputeVar(PointCopy(p), 1 << (width - 2));

            PointSetNeutral(r);

            for (int bit = 252;;)
            {
                int wb = ws_b[bit];
                if (wb != 0)
                {
                    int sign = wb >> 31;
                    int index = (wb ^ sign) >> 1;

                    PointAddVar((sign != 0), precompBaseTable[index], r);
                }

                int wp = ws_p[bit];
                if (wp != 0)
                {
                    int sign = wp >> 31;
                    int index = (wp ^ sign) >> 1;

                    PointAddVar((sign != 0), tp[index], r);
                }

                if (--bit < 0)
                    break;

                PointDouble(r);
            }
        }

        public static void Sign(byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            byte[] ctx = null;
            byte phflag = 0x00;

            ImplSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        public static void Sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
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

        public static void Sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)
        {
            byte phflag = 0x00;

            ImplSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff)
        {
            byte phflag = 0x01;

            ImplSign(sk, skOff, ctx, phflag, ph, phOff, PrehashSize, sig, sigOff);
        }

        public static void SignPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff)
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

        public static void SignPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, IDigest ph, byte[] sig, int sigOff)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.DoFinal(m, 0))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            ImplSign(sk, skOff, pk, pkOff, ctx, phflag, m, 0, m.Length, sig, sigOff);
        }

        public static bool ValidatePublicKeyFull(byte[] pk, int pkOff)
        {
            PointAffine p = new PointAffine();
            if (!DecodePointVar(pk, pkOff, false, p))
                return false;

            F.Normalize(p.x);
            F.Normalize(p.y);

            if (IsNeutralElementVar(p.x, p.y))
                return false;

            PointAccum r = new PointAccum();
            ScalarMultOrderVar(p, r);

            F.Normalize(r.x);
            F.Normalize(r.y);
            F.Normalize(r.z);

            return IsNeutralElementVar(r.x, r.y, r.z);
        }

        public static bool ValidatePublicKeyPartial(byte[] pk, int pkOff)
        {
            PointAffine p = new PointAffine();
            return DecodePointVar(pk, pkOff, false, p);
        }

        public static bool Verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)
        {
            byte[] ctx = null;
            byte phflag = 0x00;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
        }

        public static bool Verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen)
        {
            byte phflag = 0x00;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff)
        {
            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, ph, phOff, PrehashSize);
        }

        public static bool VerifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, IDigest ph)
        {
            byte[] m = new byte[PrehashSize];
            if (PrehashSize != ph.DoFinal(m, 0))
                throw new ArgumentException("ph");

            byte phflag = 0x01;

            return ImplVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, 0, m.Length);
        }
    }
}
