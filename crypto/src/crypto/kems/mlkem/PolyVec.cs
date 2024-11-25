using System;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal sealed class PolyVec
    {
        private readonly MLKemEngine m_engine;

        internal readonly Poly[] m_vec;

        internal PolyVec(MLKemEngine engine)
        {
            m_engine = engine;
            m_vec = new Poly[engine.K];
            for (int i = 0; i < engine.K; i++)
            {
                m_vec[i] = new Poly(engine);
            }
        }

        internal void Ntt()
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].PolyNtt();
            }
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].PolyInverseNttToMont();
            }
        }

        internal static void PointwiseAccountMontgomery(Poly r, PolyVec a, PolyVec b, MLKemEngine engine)
        {
            Poly t = new Poly(engine);
            Poly.BaseMultMontgomery(r, a.m_vec[0], b.m_vec[0]);
            for (int i = 1; i < engine.K; i++)
            {
                Poly.BaseMultMontgomery(t, a.m_vec[i], b.m_vec[i]);
                r.Add(t);
            }
            r.PolyReduce();
        }

        internal void Add(PolyVec a)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].Add(a.m_vec[i]);
            }
        }

        internal void Reduce()
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].PolyReduce();
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void CompressPolyVec(Span<byte> rBuf)
        {
            int pos = 0;
#else
        internal void CompressPolyVec(byte[] rBuf, int rOff)
        {
            int pos = rOff;
#endif
            ConditionalSubQ();
            if (m_engine.PolyVecCompressedBytes == m_engine.K * 320)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<short> t = stackalloc short[4];
#else
                short[] t = new short[4];
#endif

                for (int i = 0; i < m_engine.K; i++)
                {
                    short[] coeffs = m_vec[i].m_coeffs;

                    for (int j = 0; j < MLKemEngine.N / 4; j++)
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            int c_k = coeffs[4 * j + k];

                            // Avoid non-constant-time division by Q.
                            //t[k] = (short)((((c_k << 10) + (MLKemEngine.Q / 2)) / MLKemEngine.Q) & 0x3FF);
                            t[k] = (short)((((long)((c_k << 3) + (MLKemEngine.Q >> 8)) * 165141429) >> 32) & 0x3FF);
                        }
                        rBuf[pos + 0] = (byte)(t[0] >> 0);
                        rBuf[pos + 1] = (byte)((t[0] >> 8) | (t[1] << 2));
                        rBuf[pos + 2] = (byte)((t[1] >> 6) | (t[2] << 4));
                        rBuf[pos + 3] = (byte)((t[2] >> 4) | (t[3] << 6));
                        rBuf[pos + 4] = (byte)((t[3] >> 2));
                        pos += 5;
                    }
                }
            }
            else if (m_engine.PolyVecCompressedBytes == m_engine.K * 352)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<short> t = stackalloc short[8];
#else
                short[] t = new short[8];
#endif

                for (int i = 0; i < m_engine.K; i++)
                {
                    short[] coeffs = m_vec[i].m_coeffs;

                    for (int j = 0; j < MLKemEngine.N / 8; j++)
                    {
                        for (int k = 0; k < 8; k++)
                        {
                            int c_k = coeffs[8 * j + k];

                            // Avoid non-constant-time division by Q.
                            //t[k] = (short)((((c_k << 11) + (MLKemEngine.Q / 2)) / MLKemEngine.Q) & 0x7FF);
                            t[k] = (short)((((long)((c_k << 4) + (MLKemEngine.Q >> 8)) * 165141429) >> 32) & 0x7FF);
                        }
                        rBuf[pos + 0] = (byte)((t[0] >> 0));
                        rBuf[pos + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
                        rBuf[pos + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
                        rBuf[pos + 3] = (byte)((t[2] >> 2));
                        rBuf[pos + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
                        rBuf[pos + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
                        rBuf[pos + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
                        rBuf[pos + 7] = (byte)((t[5] >> 1));
                        rBuf[pos + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
                        rBuf[pos + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
                        rBuf[pos + 10] = (byte)((t[7] >> 3));
                        pos += 11;
                    }
                }
            }
            else
            {
                throw new ArgumentException("ML-KEM PolyVecCompressedBytes neither 320 * K or 352 * K!");
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void DecompressPolyVec(ReadOnlySpan<byte> cBuf)
        {
            int pos = 0;
#else
        internal void DecompressPolyVec(byte[] cBuf, int cOff)
        {
            int pos = cOff;
#endif

            if (m_engine.PolyVecCompressedBytes == (m_engine.K * 320))
            {
                for (int i = 0; i < m_engine.K; i++)
                {
                    short[] coeffs = m_vec[i].m_coeffs;
                    for (int j = 0; j < MLKemEngine.N; j += 4)
                    {
                        int c0 = cBuf[pos + 0];
                        int c1 = cBuf[pos + 1];
                        int c2 = cBuf[pos + 2];
                        int c3 = cBuf[pos + 3];
                        int c4 = cBuf[pos + 4];
                        pos += 5;

                        short t0 = (short)((c0 >> 0) | ((ushort)c1 << 8));
                        short t1 = (short)((c1 >> 2) | ((ushort)c2 << 6));
                        short t2 = (short)((c2 >> 4) | ((ushort)c3 << 4));
                        short t3 = (short)((c3 >> 6) | ((ushort)c4 << 2));

                        coeffs[j + 0] = (short)(((t0 & 0x3FF) * MLKemEngine.Q + 512) >> 10);
                        coeffs[j + 1] = (short)(((t1 & 0x3FF) * MLKemEngine.Q + 512) >> 10);
                        coeffs[j + 2] = (short)(((t2 & 0x3FF) * MLKemEngine.Q + 512) >> 10);
                        coeffs[j + 3] = (short)(((t3 & 0x3FF) * MLKemEngine.Q + 512) >> 10);
                    }
                }
            }
            else if (m_engine.PolyVecCompressedBytes == (m_engine.K * 352))
            {
                for (int i = 0; i < m_engine.K; i++)
                {
                    short[] coeffs = m_vec[i].m_coeffs;
                    for (int j = 0; j < MLKemEngine.N; j += 8)
                    {
                        int c0 = cBuf[pos + 0];
                        int c1 = cBuf[pos + 1];
                        int c2 = cBuf[pos + 2];
                        int c3 = cBuf[pos + 3];
                        int c4 = cBuf[pos + 4];
                        int c5 = cBuf[pos + 5];
                        int c6 = cBuf[pos + 6];
                        int c7 = cBuf[pos + 7];
                        int c8 = cBuf[pos + 8];
                        int c9 = cBuf[pos + 9];
                        int c10 = cBuf[pos + 10];
                        pos += 11;

                        short t0 = (short)((c0 >> 0) | ((ushort)c1 << 8));
                        short t1 = (short)((c1 >> 3) | ((ushort)c2 << 5));
                        short t2 = (short)((c2 >> 6) | ((ushort)c3 << 2) | ((ushort)(c4 << 10)));
                        short t3 = (short)((c4 >> 1) | ((ushort)c5 << 7));
                        short t4 = (short)((c5 >> 4) | ((ushort)c6 << 4));
                        short t5 = (short)((c6 >> 7) | ((ushort)c7 << 1) | ((ushort)(c8 << 9)));
                        short t6 = (short)((c8 >> 2) | ((ushort)c9 << 6));
                        short t7 = (short)((c9 >> 5) | ((ushort)c10 << 3));

                        coeffs[j + 0] = (short)(((t0 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 1] = (short)(((t1 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 2] = (short)(((t2 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 3] = (short)(((t3 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 4] = (short)(((t4 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 5] = (short)(((t5 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 6] = (short)(((t6 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        coeffs[j + 7] = (short)(((t7 & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                    }
                }
            }
            else
            {
                throw new ArgumentException("ML-KEM PolyVecCompressedBytes neither 320 * K or 352 * K!");
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void FromBytes(ReadOnlySpan<byte> pk)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].FromBytes(pk.Slice(i * MLKemEngine.PolyBytes));
            }
        }

        internal void ToBytes(Span<byte> r)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].ToBytes(r.Slice(i * MLKemEngine.PolyBytes));
            }
        }
#else
        internal void FromBytes(byte[] pk)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].FromBytes(pk, i * MLKemEngine.PolyBytes);
            }
        }

        internal void ToBytes(byte[] r)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].ToBytes(r, i * MLKemEngine.PolyBytes);
            }
        }
#endif

        private void ConditionalSubQ()
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].CondSubQ();
            }
        }
    }
}
