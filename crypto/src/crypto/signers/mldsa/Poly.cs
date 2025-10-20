using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal class Poly
    {
        private const int N = MLDsaEngine.N;

        private readonly MLDsaEngine m_engine;
        private readonly int m_polyUniformNBlocks;
        private readonly ShakeSymmetric m_symmetric;

        internal readonly int[] m_coeffs = new int[N];

        public Poly(MLDsaEngine engine)
        {
            m_engine = engine;
            m_symmetric = engine.Symmetric;
            m_polyUniformNBlocks = (768 + m_symmetric.Stream128BlockBytes - 1) / m_symmetric.Stream128BlockBytes;
        }

        internal void CopyTo(Poly z) => Array.Copy(m_coeffs, z.m_coeffs, N);

        public void UniformBlocks(byte[] seed, ushort nonce)
        {
            int buflen = m_polyUniformNBlocks * m_symmetric.Stream128BlockBytes;
            byte[] buf = new byte[buflen + 2];

            m_symmetric.Stream128Init(seed, nonce);

            m_symmetric.Stream128SqueezeBlocks(buf, 0, buflen);

            int ctr = RejectUniform(m_coeffs, 0, N, buf, buflen);
            while (ctr < N)
            {
                int off = buflen % 3;
                for (int i = 0; i < off; ++i)
                {
                    buf[i] = buf[buflen - off + i];
                }
                m_symmetric.Stream128SqueezeBlocks(buf, off, m_symmetric.Stream128BlockBytes);
                buflen = m_symmetric.Stream128BlockBytes + off;
                ctr += RejectUniform(m_coeffs, ctr, N - ctr, buf, buflen);
            }
        }

        private static int RejectUniform(int[] coeffs, int off, int len, byte[] buf, int buflen)
        {
            int ctr = 0, pos = 0;
            while (ctr < len && pos + 3 <= buflen)
            {
                uint t = buf[pos++];
                t |= (uint)buf[pos++] << 8;
                t |= (uint)buf[pos++] << 16;
                t &= 0x7FFFFF;

                if (t < MLDsaEngine.Q)
                {
                    coeffs[off + ctr++] = (int)t;
                }
            }
            return ctr;
        }

        public void UniformEta(byte[] seed, ushort nonce)
        {
            int PolyUniformEtaNBlocks, eta = m_engine.Eta;
            if (eta == 2)
            {
                PolyUniformEtaNBlocks = (136 + m_symmetric.Stream256BlockBytes - 1) / m_symmetric.Stream256BlockBytes;
            }
            else if (eta == 4)
            {
                PolyUniformEtaNBlocks = (227 + m_symmetric.Stream256BlockBytes - 1) / m_symmetric.Stream256BlockBytes;
            }
            else
            {
                throw new ArgumentException("Wrong ML-DSA Eta!");
            }

            int buflen = PolyUniformEtaNBlocks * m_symmetric.Stream256BlockBytes;

            byte[] buf = new byte[buflen];

            m_symmetric.Stream256Init(seed, nonce);
            m_symmetric.Stream256SqueezeBlocks(buf, 0, buflen);
            int ctr = RejectEta(m_coeffs, 0, N, buf, buflen, eta);

            while (ctr < N)
            {
                m_symmetric.Stream256SqueezeBlocks(buf, 0, m_symmetric.Stream256BlockBytes);
                ctr += RejectEta(m_coeffs, ctr, N - ctr, buf, m_symmetric.Stream256BlockBytes, eta);
            }
        }

        private static int RejectEta(int[] coeffs, int off, int len, byte[] buf, int buflen, int eta)
        {
            int ctr = 0, pos = 0;

            while (ctr < len && pos < buflen)
            {
                byte b = buf[pos++];
                uint t0 = (uint)b & 0x0F;
                uint t1 = (uint)b >> 4;
                if (eta == 2)
                {
                    if (t0 < 15)
                    {
                        t0 = t0 - (205 * t0 >> 10) * 5;
                        coeffs[off + ctr++] = (int)(2 - t0);
                    }
                    if (t1 < 15 && ctr < len)
                    {
                        t1 = t1 - (205 * t1 >> 10) * 5;
                        coeffs[off + ctr++] = (int)(2 - t1);
                    }
                }
                else if (eta == 4)
                {
                    if (t0 < 9)
                    {
                        coeffs[off + ctr++] = (int)(4 - t0);
                    }
                    if (t1 < 9 && ctr < len)
                    {
                        coeffs[off + ctr++] = (int)(4 - t1);
                    }
                }
            }
            return ctr;
        }

        public void PointwiseMontgomery(Poly v, Poly w)
        {
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] = Reduce.MontgomeryReduce((long)((long)v.m_coeffs[i] * (long)w.m_coeffs[i]));
            }
        }

        public void PointwiseAccountMontgomery(PolyVec u, PolyVec v)
        {
            Debug.Assert(u.Length == m_engine.L);
            Debug.Assert(v.Length == m_engine.L);

            Poly t = new Poly(m_engine);

            PointwiseMontgomery(u[0], v[0]);

            for (int i = 1; i < m_engine.L; ++i)
            {
                t.PointwiseMontgomery(u[i], v[i]);
                Add(t);
            }
        }

        public void Add(Poly a)
        {
            for (int i = 0; i < N; i++)
            {
                m_coeffs[i] += a.m_coeffs[i];
            }
        }

        public void Subtract(Poly b)
        {
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] -= b.m_coeffs[i];
            }
        }

        public void ReducePoly()
        {
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] = Reduce.Reduce32(m_coeffs[i]);
            }
        }

        public void PolyNtt() => Ntt.NTT(m_coeffs);

        public void InverseNttToMont() => Ntt.InverseNttToMont(m_coeffs);

        public void ConditionalAddQ()
        {
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] = Reduce.ConditionalAddQ(m_coeffs[i]);
            }
        }

        public void Power2Round(Poly a) => Rounding.Power2RoundAll(m_coeffs, a.m_coeffs);

        public void PolyT0Pack(byte[] r, int off)
        {
            const int m = 1 << (MLDsaEngine.D - 1);

            for (int i = 0; i < N / 8; ++i)
            {
                int t0 = m - m_coeffs[8 * i + 0];
                int t1 = m - m_coeffs[8 * i + 1];
                int t2 = m - m_coeffs[8 * i + 2];
                int t3 = m - m_coeffs[8 * i + 3];
                int t4 = m - m_coeffs[8 * i + 4];
                int t5 = m - m_coeffs[8 * i + 5];
                int t6 = m - m_coeffs[8 * i + 6];
                int t7 = m - m_coeffs[8 * i + 7];

                Pack.UInt32_To_LE((uint)(t0       | t1 << 13 | t2 << 26           ), r, off + 13 * i + 0);
                Pack.UInt32_To_LE((uint)(t2 >>  6 | t3 <<  7 | t4 << 20           ), r, off + 13 * i + 4);
                Pack.UInt32_To_LE((uint)(t4 >> 12 | t5 <<  1 | t6 << 14 | t7 << 27), r, off + 13 * i + 8);
                r[off + 13 * i + 12] = (byte)(t7 >> 5);
            }
        }

        public void PolyT0Unpack(byte[] a, int off)
        {
            const int m = 1 << (MLDsaEngine.D - 1);

            for (int i = 0; i < N / 8; ++i)
            {
                uint t0 = Pack.LE_To_UInt32(a, off + 13 * i + 0);
                uint t1 = Pack.LE_To_UInt32(a, off + 13 * i + 4);
                uint t2 = Pack.LE_To_UInt32(a, off + 13 * i + 8);
                uint t3 = a[off + 13 * i + 12];

                m_coeffs[8 * i + 0] = m - ((int)t0 & 0x1FFF);
                m_coeffs[8 * i + 1] = m - ((int)(t0 >> 13) & 0x1FFF);
                m_coeffs[8 * i + 2] = m - ((int)(t0 >> 26 | t1 << 6) & 0x1FFF);
                m_coeffs[8 * i + 3] = m - ((int)(t1 >> 7) & 0x1FFF);
                m_coeffs[8 * i + 4] = m - ((int)(t1 >> 20 | t2 << 12) & 0x1FFF);
                m_coeffs[8 * i + 5] = m - ((int)(t2 >> 1) & 0x1FFF);
                m_coeffs[8 * i + 6] = m - ((int)(t2 >> 14) & 0x1FFF);
                m_coeffs[8 * i + 7] = m - ((int)(t2 >> 27 | t3 << 5) & 0x1FFF);
            }
        }

        public void PolyT1Pack(byte[] buf, int bufOff)
        {
            for (int i = 0; i < N / 4; ++i)
            {
                int t0 = m_coeffs[4 * i + 0];
                int t1 = m_coeffs[4 * i + 1];
                int t2 = m_coeffs[4 * i + 2];
                int t3 = m_coeffs[4 * i + 3];

                Pack.UInt32_To_LE((uint)(t0 | t1 << 10 | t2 << 20 | t3 << 30), buf, bufOff + 5 * i);
                buf[bufOff + 5 * i + 4] = (byte)(t3 >> 2);
            }
        }

        public void PolyT1Unpack(byte[] a, int aOff)
        {
            for (int i = 0; i < N / 4; ++i)
            {
                uint t0 = Pack.LE_To_UInt32(a, aOff + 5 * i);
                uint t1 = a[aOff + 5 * i + 4];

                m_coeffs[4 * i + 0] = (int)t0 & 0x3FF;
                m_coeffs[4 * i + 1] = (int)(t0 >> 10) & 0x3FF;
                m_coeffs[4 * i + 2] = (int)(t0 >> 20) & 0x3FF;
                m_coeffs[4 * i + 3] = (int)(t0 >> 30 | t1 << 2) & 0x3FF;
            }
        }

        public void PolyEtaPack(byte[] r, int off)
        {
            int eta = m_engine.Eta;
            if (eta == 2)
            {
                for (int i = 0; i < N / 8; ++i)
                {
                    byte t0 = (byte)(eta - m_coeffs[8 * i + 0]);
                    byte t1 = (byte)(eta - m_coeffs[8 * i + 1]);
                    byte t2 = (byte)(eta - m_coeffs[8 * i + 2]);
                    byte t3 = (byte)(eta - m_coeffs[8 * i + 3]);
                    byte t4 = (byte)(eta - m_coeffs[8 * i + 4]);
                    byte t5 = (byte)(eta - m_coeffs[8 * i + 5]);
                    byte t6 = (byte)(eta - m_coeffs[8 * i + 6]);
                    byte t7 = (byte)(eta - m_coeffs[8 * i + 7]);

                    r[off + 3 * i + 0] = (byte)((t0 >> 0) | (t1 << 3) | (t2 << 6));
                    r[off + 3 * i + 1] = (byte)((t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7));
                    r[off + 3 * i + 2] = (byte)((t5 >> 1) | (t6 << 2) | (t7 << 5));
                }
            }
            else if (eta == 4)
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    byte t0 = (byte)(eta - m_coeffs[2 * i + 0]);
                    byte t1 = (byte)(eta - m_coeffs[2 * i + 1]);
                    r[off + i] = (byte)(t0 | t1 << 4);
                }
            }
            else
            {
                throw new ArgumentException("Eta needs to be 2 or 4!");
            }
        }

        public void PolyEtaUnpack(byte[] a, int off)
        {
            int eta = m_engine.Eta;
            if (eta == 2)
            {
                for (int i = 0; i < N / 8; ++i)
                {
                    m_coeffs[8 * i + 0] = eta - (a[off + 3 * i + 0] & 7);
                    m_coeffs[8 * i + 1] = eta - ((a[off + 3 * i + 0] >> 3) & 7);
                    m_coeffs[8 * i + 2] = eta - ((a[off + 3 * i + 0] >> 6 | a[off + 3 * i + 1] << 2) & 7);
                    m_coeffs[8 * i + 3] = eta - ((a[off + 3 * i + 1] >> 1) & 7);
                    m_coeffs[8 * i + 4] = eta - ((a[off + 3 * i + 1] >> 4) & 7);
                    m_coeffs[8 * i + 5] = eta - ((a[off + 3 * i + 1] >> 7 | a[off + 3 * i + 2] << 1) & 7);
                    m_coeffs[8 * i + 6] = eta - ((a[off + 3 * i + 2] >> 2) & 7);
                    m_coeffs[8 * i + 7] = eta - ((a[off + 3 * i + 2] >> 5) & 7);
                }
            }
            else if (eta == 4)
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    m_coeffs[2 * i + 0] = eta - (a[off + i] & 0x0F);
                    m_coeffs[2 * i + 1] = eta - (a[off + i] >> 4);
                }
            }
        }

        public void UniformGamma1(byte[] seed, ushort nonce)
        {
            byte[] buf = new byte[m_engine.PolyUniformGamma1NBytes * m_symmetric.Stream256BlockBytes];
            m_symmetric.Stream256Init(seed, nonce);
            m_symmetric.Stream256SqueezeBlocks(buf, 0, buf.Length);
            UnpackZ(buf, 0);
        }

        public void PackZ(byte[] r, int offset)
        {
            int gamma1 = m_engine.Gamma1;
            if (gamma1 == (1 << 17))
            {
                for (int i = 0; i < N / 4; ++i)
                {
                    uint t0 = (uint)(gamma1 - m_coeffs[4 * i + 0]);
                    uint t1 = (uint)(gamma1 - m_coeffs[4 * i + 1]);
                    uint t2 = (uint)(gamma1 - m_coeffs[4 * i + 2]);
                    uint t3 = (uint)(gamma1 - m_coeffs[4 * i + 3]);

                    Pack.UInt32_To_LE(t0 | t1 << 18, r, offset + 9 * i + 0);
                    Pack.UInt32_To_LE(t1 >> 14 | t2 << 4 | t3 << 22, r, offset + 9 * i + 4);
                    r[offset + 9 * i + 8] = (byte)(t3 >> 10);
                }
            }
            else if (gamma1 == (1 << 19))
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    uint t0 = (uint)(gamma1 - m_coeffs[2 * i + 0]);
                    uint t1 = (uint)(gamma1 - m_coeffs[2 * i + 1]);

                    Pack.UInt32_To_LE(t0 | t1 << 20, r, offset + 5 * i + 0);
                    r[offset + 5 * i + 4] = (byte)(t1 >> 12);
                }
            }
            else
            {
                throw new ArgumentException("Wrong ML-DSA Gamma1!");
            }
        }

        internal void UnpackZ(byte[] a, int aOff)
        {
            int gamma1 = m_engine.Gamma1;
            if (gamma1 == (1 << 17))
            {
                for (int i = 0; i < N / 4; ++i)
                {
                    uint t0 = Pack.LE_To_UInt32(a, aOff + 9 * i + 0);
                    uint t1 = Pack.LE_To_UInt32(a, aOff + 9 * i + 4);
                    uint t2 = a[aOff + 9 * i + 8];

                    m_coeffs[4 * i + 0] = gamma1 - ((int)t0 & 0x3FFFF);
                    m_coeffs[4 * i + 1] = gamma1 - ((int)(t0 >> 18 | t1 << 14) & 0x3FFFF);
                    m_coeffs[4 * i + 2] = gamma1 - ((int)(t1 >> 4) & 0x3FFFF);
                    m_coeffs[4 * i + 3] = gamma1 - ((int)(t1 >> 22 | t2 << 10) & 0x3FFFF);
                }
            }
            else if (gamma1 == (1 << 19))
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    uint t0 = Pack.LE_To_UInt32(a, aOff + 5 * i + 0);
                    uint t1 = a[aOff + 5 * i + 4];

                    m_coeffs[2 * i + 0] = gamma1 - ((int)t0 & 0xFFFFF);
                    m_coeffs[2 * i + 1] = gamma1 - ((int)(t0 >> 20 | t1 << 12) & 0xFFFFF);
                }
            }
            else
            {
                throw new ArgumentException("Wrong ML-DSA Gamma1!");
            }
        }

        public void Decompose(Poly a) => Rounding.DecomposeAll(a.m_coeffs, m_coeffs, m_engine.Gamma2);

        internal void PackW1(byte[] r, int off)
        {
            int gamma2 = m_engine.Gamma2;
            if (gamma2 == (MLDsaEngine.Q - 1) / 88)
            {
                for (int i = 0; i < N / 4; ++i)
                {
                    r[off + 3 * i + 0] = (byte)(((byte)m_coeffs[4 * i + 0]) | (m_coeffs[4 * i + 1] << 6));
                    r[off + 3 * i + 1] = (byte)((byte)(m_coeffs[4 * i + 1] >> 2) | (m_coeffs[4 * i + 2] << 4));
                    r[off + 3 * i + 2] = (byte)((byte)(m_coeffs[4 * i + 2] >> 4) | (m_coeffs[4 * i + 3] << 2));
                }
            }
            else if (gamma2 == (MLDsaEngine.Q - 1) / 32)
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    r[off + i] = (byte)(m_coeffs[2 * i + 0] | (m_coeffs[2 * i + 1] << 4));
                }
            }
        }

        internal void Challenge(byte[] seed, int seedOff, int seedLen)
        {
            byte[] buf = new byte[m_symmetric.Stream256BlockBytes];

            ShakeDigest ShakeDigest256 = new ShakeDigest(256);
            ShakeDigest256.BlockUpdate(seed, seedOff, seedLen);
            ShakeDigest256.Output(buf, 0, m_symmetric.Stream256BlockBytes);

            ulong signs = Pack.LE_To_UInt64(buf);
            int bufPos = 8;

            Arrays.Fill(m_coeffs, from: 0, to: N, 0x00);

            for (int i = N - m_engine.Tau; i < N; ++i)
            {
                int b;
                do
                {
                    if (bufPos >= m_symmetric.Stream256BlockBytes)
                    {
                        ShakeDigest256.Output(buf, 0, m_symmetric.Stream256BlockBytes);
                        bufPos = 0;
                    }
                    b = buf[bufPos++];
                }
                while (b > i);

                m_coeffs[i] = m_coeffs[b];
                m_coeffs[b] = (int)(1 - 2 * (signs & 1));
                signs >>= 1;
            }
        }

        public bool CheckNorm(int B)
        {
            if (B > (MLDsaEngine.Q - 1) / 8)
                return true;

            for (int i = 0; i < N; ++i)
            {
                int t = m_coeffs[i] >> 31;
                t = m_coeffs[i] - (t & 2 * m_coeffs[i]);

                if (t >= B)
                    return true;
            }
            return false;
        }
        public int PolyMakeHint(Poly a0, Poly a1)
        {
            int s = 0;
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] = Rounding.MakeHint(a0.m_coeffs[i], a1.m_coeffs[i], m_engine);
                s += m_coeffs[i];
            }
            return s;
        }

        public void PolyUseHint(Poly a, Poly h)
        {
            int gamma2 = m_engine.Gamma2;
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] = Rounding.UseHint(a.m_coeffs[i], h.m_coeffs[i], gamma2);
            }
        }

        public void ShiftLeft()
        {
            for (int i = 0; i < N; ++i)
            {
                m_coeffs[i] <<= MLDsaEngine.D;
            }
        }
    }
}
