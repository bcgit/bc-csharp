using System;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
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

        internal void CompressPolyVec(byte[] r)
        {
            ConditionalSubQ();
            int count = 0;
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
                        r[count + 0] = (byte)(t[0] >> 0);
                        r[count + 1] = (byte)((t[0] >> 8) | (t[1] << 2));
                        r[count + 2] = (byte)((t[1] >> 6) | (t[2] << 4));
                        r[count + 3] = (byte)((t[2] >> 4) | (t[3] << 6));
                        r[count + 4] = (byte)((t[3] >> 2));
                        count += 5;
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
                        r[count + 0] = (byte)((t[0] >> 0));
                        r[count + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
                        r[count + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
                        r[count + 3] = (byte)((t[2] >> 2));
                        r[count + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
                        r[count + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
                        r[count + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
                        r[count + 7] = (byte)((t[5] >> 1));
                        r[count + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
                        r[count + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
                        r[count + 10] = (byte)((t[7] >> 3));
                        count += 11;
                    }
                }
            }
            else
            {
                throw new ArgumentException("ML-KEM PolyVecCompressedBytes neither 320 * K or 352 * K!");
            }
        }

        internal void DecompressPolyVec(byte[] compressedCipherText)
        {
            int count = 0;

            if (m_engine.PolyVecCompressedBytes == (m_engine.K * 320))
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<short> t = stackalloc short[4];
#else
                short[] t = new short[4];
#endif

                for (int i = 0; i < m_engine.K; i++)
                {
                    for (int j = 0; j < MLKemEngine.N / 4; j++)
                    {
                        t[0] = (short)(((compressedCipherText[count] & 0xFF) >> 0) | ((ushort)(compressedCipherText[count + 1] & 0xFF) << 8));
                        t[1] = (short)(((compressedCipherText[count + 1] & 0xFF) >> 2) | ((ushort)(compressedCipherText[count + 2] & 0xFF) << 6));
                        t[2] = (short)(((compressedCipherText[count + 2] & 0xFF) >> 4) | ((ushort)(compressedCipherText[count + 3] & 0xFF) << 4));
                        t[3] = (short)(((compressedCipherText[count + 3] & 0xFF) >> 6) | ((ushort)(compressedCipherText[count + 4] & 0xFF) << 2));
                        count += 5;
                        for (int k = 0; k < 4; k++)
                        {
                            m_vec[i].m_coeffs[4 * j + k] = (short)(((t[k] & 0x3FF) * MLKemEngine.Q + 512) >> 10);
                        }
                    }
                }
            }
            else if (m_engine.PolyVecCompressedBytes == (m_engine.K * 352))
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<short> t = stackalloc short[8];
#else
                short[] t = new short[8];
#endif

                for (int i = 0; i < m_engine.K; i++)
                {
                    for (int j = 0; j < MLKemEngine.N / 8; j++)
                    {
                        t[0] = (short)(((compressedCipherText[count] & 0xFF) >> 0) | ((ushort)(compressedCipherText[count + 1] & 0xFF) << 8));
                        t[1] = (short)(((compressedCipherText[count + 1] & 0xFF) >> 3) | ((ushort)(compressedCipherText[count + 2] & 0xFF) << 5));
                        t[2] = (short)(((compressedCipherText[count + 2] & 0xFF) >> 6) | ((ushort)(compressedCipherText[count + 3] & 0xFF) << 2) | ((ushort)((compressedCipherText[count + 4] & 0xFF) << 10)));
                        t[3] = (short)(((compressedCipherText[count + 4] & 0xFF) >> 1) | ((ushort)(compressedCipherText[count + 5] & 0xFF) << 7));
                        t[4] = (short)(((compressedCipherText[count + 5] & 0xFF) >> 4) | ((ushort)(compressedCipherText[count + 6] & 0xFF) << 4));
                        t[5] = (short)(((compressedCipherText[count + 6] & 0xFF) >> 7) | ((ushort)(compressedCipherText[count + 7] & 0xFF) << 1) | ((ushort)((compressedCipherText[count + 8] & 0xFF) << 9)));
                        t[6] = (short)(((compressedCipherText[count + 8] & 0xFF) >> 2) | ((ushort)(compressedCipherText[count + 9] & 0xFF) << 6));
                        t[7] = (short)(((compressedCipherText[count + 9] & 0xFF) >> 5) | ((ushort)(compressedCipherText[count + 10] & 0xFF) << 3));
                        count += 11;
                        for (int k = 0; k < 8; k++)
                        {
                            m_vec[i].m_coeffs[8 * j + k] = (short)(((t[k] & 0x7FF) * MLKemEngine.Q + 1024) >> 11);
                        }
                    }
                }
            }
            else
            {
                throw new ArgumentException("ML-KEM PolyVecCompressedBytes neither 320 * K or 352 * K!");
            }
        }

        internal void ToBytes(byte[] r)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].ToBytes(r, i * MLKemEngine.PolyBytes);
            }
        }

        internal void FromBytes(byte[] pk)
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].FromBytes(pk, i * MLKemEngine.PolyBytes);
            }
        }

        private void ConditionalSubQ()
        {
            for (int i = 0; i < m_engine.K; i++)
            {
                m_vec[i].CondSubQ();
            }
        }
    }
}
