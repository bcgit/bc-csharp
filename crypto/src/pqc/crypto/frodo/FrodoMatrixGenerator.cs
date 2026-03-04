using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public abstract class FrodoMatrixGenerator
    {
        internal readonly int m_n;
        internal readonly int m_q;

        public FrodoMatrixGenerator(int n, int q)
        {
            Debug.Assert((n & 7) == 0);

            m_n = n;
            m_q = q;
        }

        internal abstract short[] GenMatrix(byte[] seed, int seedOff, int seedLen);

        internal class Shake128MatrixGenerator
            : FrodoMatrixGenerator
        {
            internal Shake128MatrixGenerator(int n, int q)
                : base(n, q)
            {
            }

            internal override short[] GenMatrix(byte[] seed, int seedOff, int seedLen)
            {
                short[] A = new short[m_n * m_n];
                byte[] tmp = new byte[(16 * m_n) / 8];
                byte[] b = new byte[2 + seedLen];
                Array.Copy(seed, seedOff, b, 2, seedLen);
                uint qMask32 = (uint)(m_q - 1) * 0x10001U;

                ShakeDigest digest = new ShakeDigest(128);

                for (int i = 0; i < m_n; i++)
                {
                    // 1. b = i || seedA in {0,1}^{16 + len_seedA}, where i is encoded as 16-bit LE
                    Pack.UInt16_To_LE((ushort)i, b);

                    // 2. c_{i,0} || c_{i,1} || ... || c_{i,n-1} = SHAKE128(b, 16n) (length in bits) where each c_{i,j}
                    // is parsed as 16-bit LE
                    digest.BlockUpdate(b, 0, b.Length);
                    digest.OutputFinal(tmp, 0, tmp.Length);

                    for (int j = 0; j < m_n; j += 8)
                    {
                        uint k01 = Pack.LE_To_UInt32(tmp, (2 * j) +  0) & qMask32;
                        uint k23 = Pack.LE_To_UInt32(tmp, (2 * j) +  4) & qMask32;
                        uint k45 = Pack.LE_To_UInt32(tmp, (2 * j) +  8) & qMask32;
                        uint k67 = Pack.LE_To_UInt32(tmp, (2 * j) + 12) & qMask32;

                        A[i * m_n + j + 0] = (short)k01;
                        A[i * m_n + j + 1] = (short)(k01 >> 16);
                        A[i * m_n + j + 2] = (short)k23;
                        A[i * m_n + j + 3] = (short)(k23 >> 16);
                        A[i * m_n + j + 4] = (short)k45;
                        A[i * m_n + j + 5] = (short)(k45 >> 16);
                        A[i * m_n + j + 6] = (short)k67;
                        A[i * m_n + j + 7] = (short)(k67 >> 16);
                    }
                }
                return A;
            }
        }

        internal class Aes128MatrixGenerator
            : FrodoMatrixGenerator
        {
            internal Aes128MatrixGenerator(int n, int q)
                : base(n, q)
            {
            }

            internal override short[] GenMatrix(byte[] seed, int seedOff, int seedLen)
            {
                // """Generate matrix A using AES-128 (FrodoKEM specification, Algorithm 7)"""
                // A = [[None for j in range(self.n)] for i in range(self.n)]
                short[] A = new short[m_n * m_n];
                byte[] b = new byte[16];
                byte[] c = new byte[16];
                uint qMask32 = (uint)(m_q - 1) * 0x10001U;

                IBlockCipher cipher = AesUtilities.CreateEngine();
                cipher.Init(true, new KeyParameter(seed, seedOff, seedLen));

                for (int i = 0; i < m_n; i++)
                {
                    Pack.UInt16_To_LE((ushort)i, b, 0);

                    for (int j = 0; j < m_n; j += 8)
                    {
                        // 3. b = i || j || 0 || ... || 0 in {0,1}^128, where i and j are encoded as 16-bit LE
                        Pack.UInt16_To_LE((ushort)j, b, 2);
                        // 4. c = AES128(seedA, b)
                        cipher.ProcessBlock(b, 0, c, 0);

                        uint k01 = Pack.LE_To_UInt32(c,  0) & qMask32;
                        uint k23 = Pack.LE_To_UInt32(c,  4) & qMask32;
                        uint k45 = Pack.LE_To_UInt32(c,  8) & qMask32;
                        uint k67 = Pack.LE_To_UInt32(c, 12) & qMask32;

                        // 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit LE
                        A[i * m_n + j + 0] = (short)k01;
                        A[i * m_n + j + 1] = (short)(k01 >> 16);
                        A[i * m_n + j + 2] = (short)k23;
                        A[i * m_n + j + 3] = (short)(k23 >> 16);
                        A[i * m_n + j + 4] = (short)k45;
                        A[i * m_n + j + 5] = (short)(k45 >> 16);
                        A[i * m_n + j + 6] = (short)k67;
                        A[i * m_n + j + 7] = (short)(k67 >> 16);
                    }
                }
                return A;
            }
        }
    }
}
