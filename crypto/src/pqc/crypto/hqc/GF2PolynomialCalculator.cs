using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class GF2PolynomialCalculator
    {
        static volatile int TABLE = 16;
        static volatile int WORD = 64;
        static void Mod(ulong[] res, ulong[] a, int n, int nByte64)
        {
            ulong r;
            ulong carry;
            for (int i = 0; i < nByte64; i++)
            {
                r = a[i + nByte64 - 1] >> (n & 0x3F);
                carry = a[i + nByte64] << (64 - (n & 0x3F));
                res[i] = a[i] ^ r ^ carry;
            }
            res[nByte64 - 1] &= (ulong) Utils.BitMask(n, 64);
        }

        static void Swap(int[] table, int fisrtIndex, int secIndex)
        {
            int tmp = table[fisrtIndex];
            table[fisrtIndex] = table[secIndex];
            table[secIndex] = tmp;
        }

        static void FastConvolutionMult(ulong[] res, int[] a, long[] b, int weight, int nByte64, int we, HqcKeccakRandomGenerator random)
        {
            ulong carry;
            int dec, s;
            ulong[] table = new ulong[TABLE * (nByte64 + 1)];
            int[] permutedTable = new int[TABLE];
            int[] permutationTable = new int[TABLE];
            int[] permutedSparseVect = new int[we];
            int[] permutationSparseVect = new int[we];

            for (int i = 0; i < 16; i++)
            {
                permutedTable[i] = i;
            }

            byte[] permutationTableByte = new byte[TABLE*2];
            random.ExpandSeed(permutationTableByte, TABLE << 1);

            Utils.FromByteArrayToByte16Array(permutationTable, permutationTableByte);

            for (int i = 0; i < TABLE - 1; i++)
            {
                Swap(permutedTable, i, i + permutationTable[i] % (TABLE - i));
            }

            //int count = (permutedTable[0] * (nByte64 + 1));
            int idx = permutedTable[0] * (nByte64 + 1);
            ulong[] pt = new ulong[nByte64+1];

            for (int i = 0; i < nByte64; i++)
            {
                pt[i] = (ulong) b[i];
            }

            pt[nByte64] = 0x0UL;

            Array.Copy(pt, 0, table, idx, pt.Length);

            for (int i = 1; i < TABLE; i++)
            {
                carry = 0x0UL;
                idx = permutedTable[i] * (nByte64 + 1);
                ulong[] pt2 = new ulong[nByte64+1];

                for (int j = 0; j < nByte64; j++)
                {
                    pt2[j] = ((ulong) b[j] << i) ^ carry;
                    carry = ((ulong) b[j] >> ((WORD - i)));
                }

                pt2[nByte64] = carry;
                Array.Copy(pt2, 0, table, idx, pt2.Length);
            }

            for (int i = 0; i < weight; i++)
            {
                permutedSparseVect[i] = i;
            }

            byte[] permutationSparseVectBytes = new byte[we * 2];
            random.ExpandSeed(permutationSparseVectBytes, weight << 1);

            Utils.FromByteArrayToByte16Array(permutationSparseVect, permutationSparseVectBytes);

            for (int i = 0; i < (weight - 1); i++)
            {
                Swap(permutedSparseVect, i, i + permutationSparseVect[i] % (weight - i));
            }

            int[] resByte16 = new int[res.Length * 4];

            for (int i = 0; i < weight; i++)
            {
                carry = 0x0UL;
                dec = a[permutedSparseVect[i]] & 0xf;
                s = a[permutedSparseVect[i]] >> 4;

                idx = (permutedTable[dec] * (nByte64 + 1));
                ulong[] pt3 = new ulong[nByte64+1];
                for (int j = 0; j< pt3.Length; j++)
                {
                    pt3[j] = table[j + idx];
                }
                int count = s;
                for (int j = 0; j < nByte64 + 1; j++)
                {
                    ulong tmp = (ulong) (((ulong) resByte16[count]) | (((ulong) resByte16[count + 1]) << 16) | ((ulong) (resByte16[count + 2]) << 32) | (((ulong)(resByte16[count + 3])) << 48));
                    tmp ^= pt3[j];
                    AddULongToByte16Array(resByte16, tmp, count);
                    count += 4;
                }
            }
            Utils.FromByte16ArrayToLongArray(res, resByte16);
        }

        internal static void ModMult(ulong[] res, int[] a, long[] b, int weight,int n,  int nByte64, int we,  HqcKeccakRandomGenerator random)
        {
            ulong[] tmp = new ulong[(nByte64 << 1) + 1];
            FastConvolutionMult(tmp, a, b, weight, nByte64, we, random);
            Mod(res, tmp, n, nByte64);
        }

        private static void AddULongToByte16Array(int[] array, ulong t, int startIndex)
        {
            ulong[] tmp = new ulong[] { t };
            int[] tmpArray = new int[4];
            Utils.FromULongArrayToByte16Array(tmpArray, tmp);
            Array.Copy(tmpArray, 0, array, startIndex, tmpArray.Length);
        }

        internal static void AddBytes(byte[] res, byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                res[i] =(byte) (a[i] ^ b[i]);
            }
        }

        internal static void AddLongs(ulong[] res, ulong[] a, long[] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                res[i] = a[i] ^ (ulong) b[i];
            }
        }

        internal static void AddULongs(ulong[] res, ulong[] a, ulong[] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                res[i] = a[i] ^ b[i];
            }
        }
    }
}
