using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public abstract class FrodoMatrixGenerator
    {
        int n;
        int q;

        public FrodoMatrixGenerator(int n, int q)
        {
            this.n = n;
            this.q = q;
        }

        internal abstract short[] GenMatrix(byte[] seedA);

        internal class Shake128MatrixGenerator
            : FrodoMatrixGenerator
        {
            public Shake128MatrixGenerator(int n, int q)
                : base(n, q)
            {
            }

            internal override short[] GenMatrix(byte[] seedA)
            {
                short[] A = new short[n * n];
                ushort i, j;
                byte[] tmp = new byte[(16 * n) / 8];
                byte[] b = new byte[2 + seedA.Length];
                Array.Copy(seedA, 0, b, 2, seedA.Length);
                uint qMask32 = ((uint)(q - 1) << 16) | (ushort)(q - 1);

                IXof digest = new ShakeDigest(128);

                for (i = 0; i < n; i++)
                {
                    // 1. b = i || seedA in {0,1}^{16 + len_seedA}, where i is encoded as a 16-bit integer in little-endian byte order
                    Pack.UInt16_To_LE(i, b);

                    // 2. c_{i,0} || c_{i,1} || ... || c_{i,n-1} = SHAKE128(b, 16n) (length in bits) where each c_{i,j} is parsed as a 16-bit integer in little-endian byte order format
                    digest.BlockUpdate(b, 0, b.Length);
                    digest.OutputFinal(tmp, 0, tmp.Length);
                    for (j = 0; j < n; j += 8)
                    {
                        uint k01 = Pack.LE_To_UInt32(tmp, (2 * j) +  0) & qMask32;
                        uint k23 = Pack.LE_To_UInt32(tmp, (2 * j) +  4) & qMask32;
                        uint k45 = Pack.LE_To_UInt32(tmp, (2 * j) +  8) & qMask32;
                        uint k67 = Pack.LE_To_UInt32(tmp, (2 * j) + 12) & qMask32;
                        // 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit integers each in little-endian byte order
                        A[i * n + j + 0] = (short)k01;
                        A[i * n + j + 1] = (short)(k01 >> 16);
                        A[i * n + j + 2] = (short)k23;
                        A[i * n + j + 3] = (short)(k23 >> 16);
                        A[i * n + j + 4] = (short)k45;
                        A[i * n + j + 5] = (short)(k45 >> 16);
                        A[i * n + j + 6] = (short)k67;
                        A[i * n + j + 7] = (short)(k67 >> 16);
                    }
                }
                return A;
            }
        }

        internal class Aes128MatrixGenerator
            : FrodoMatrixGenerator
        {
            public Aes128MatrixGenerator(int n, int q)
                : base(n, q)
            {
            }

            internal override short[] GenMatrix(byte[] seedA)
            {
                // """Generate matrix A using AES-128 (FrodoKEM specification, Algorithm 7)"""
                // A = [[None for j in range(self.n)] for i in range(self.n)]
                short[] A = new short[n * n];
                byte[] b = new byte[16];
                byte[] c = new byte[16];
                uint qMask32 = ((uint)(q - 1) << 16) | (ushort)(q - 1);

                IBlockCipher cipher = AesUtilities.CreateEngine();
                cipher.Init(true, new KeyParameter(seedA));

                // 1. for i = 0; i < n; i += 1
                for (int i = 0; i < n; i++)
                {
                    Pack.UInt16_To_LE((ushort)i, b, 0);

                    // 2. for j = 0; j < n; j += 8
                    for (int j = 0; j < n; j += 8)
                    {
                        // 3. b = i || j || 0 || ... || 0 in {0,1}^128, where i and j are encoded as 16-bit integers in little-endian byte order
                        Pack.UInt16_To_LE((ushort)j, b, 2);
                        // 4. c = AES128(seedA, b)
                        cipher.ProcessBlock(b, 0, c, 0);
                        // 5. for k = 0; k < 8; k += 1
                        uint k01 = Pack.LE_To_UInt32(c,  0) & qMask32;
                        uint k23 = Pack.LE_To_UInt32(c,  4) & qMask32;
                        uint k45 = Pack.LE_To_UInt32(c,  8) & qMask32;
                        uint k67 = Pack.LE_To_UInt32(c, 12) & qMask32;
                        // 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit integers each in little-endian byte order
                        A[i * n + j + 0] = (short)k01;
                        A[i * n + j + 1] = (short)(k01 >> 16);
                        A[i * n + j + 2] = (short)k23;
                        A[i * n + j + 3] = (short)(k23 >> 16);
                        A[i * n + j + 4] = (short)k45;
                        A[i * n + j + 5] = (short)(k45 >> 16);
                        A[i * n + j + 6] = (short)k67;
                        A[i * n + j + 7] = (short)(k67 >> 16);
                    }
                }
                return A;
            }
        }
    }
}
