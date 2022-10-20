using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
using System.Runtime.InteropServices;
#endif

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class GF2PolynomialCalculator
    {
        private const int TABLE = 16;

        static void Mod(ulong[] res, ulong[] a, int n, int nByte64)
        {
            for (int i = 0; i < nByte64; i++)
            {
                ulong r = a[i + nByte64 - 1] >> (n & 0x3F);
                ulong carry = a[i + nByte64] << (64 - (n & 0x3F));
                res[i] = a[i] ^ r ^ carry;
            }
            res[nByte64 - 1] &= Utils.BitMask((ulong)n, 64);
        }

        static void Swap(int[] table, int firstIndex, int secondIndex)
        {
            int tmp = table[firstIndex];
            table[firstIndex] = table[secondIndex];
            table[secondIndex] = tmp;
        }

        static void FastConvolutionMult(ulong[] res, int[] a, ulong[] b, int weight, int nByte64, int we,
            HqcKeccakRandomGenerator random)
        {
            int[] permutedTable = new int[TABLE];
            for (int i = 0; i < 16; i++)
            {
                permutedTable[i] = i;
            }

            byte[] permutationTableByte = new byte[TABLE*2];
            random.ExpandSeed(permutationTableByte, TABLE << 1);

            int[] permutationTable = new int[TABLE];
            Utils.FromByteArrayToByte16Array(permutationTable, permutationTableByte);

            for (int i = 0; i < TABLE - 1; i++)
            {
                Swap(permutedTable, i, i + permutationTable[i] % (TABLE - i));
            }

            ulong[] table = new ulong[TABLE * (nByte64 + 1)];
            int idx = permutedTable[0] * (nByte64 + 1);
            Array.Copy(b, 0, table, idx, nByte64);
            table[idx + nByte64] = 0UL;

            for (int i = 1; i < TABLE; i++)
            {
                idx = permutedTable[i] * (nByte64 + 1);
                table[idx + nByte64] = Nat.ShiftUpBits64(nByte64, b, 0, i, 0UL, table, idx);
            }

            int[] permutedSparseVect = new int[we];
            for (int i = 0; i < weight; i++)
            {
                permutedSparseVect[i] = i;
            }

            byte[] permutationSparseVectBytes = new byte[we * 2];
            random.ExpandSeed(permutationSparseVectBytes, weight << 1);

            int[] permutationSparseVect = new int[we];
            Utils.FromByteArrayToByte16Array(permutationSparseVect, permutationSparseVectBytes);

            for (int i = 0; i < (weight - 1); i++)
            {
                Swap(permutedSparseVect, i, i + permutationSparseVect[i] % (weight - i));
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> resBytes = MemoryMarshal.Cast<ulong, byte>(res);
            for (int i = 0; i < weight; i++)
            {
                int dec = a[permutedSparseVect[i]] & 0xf;
                int s = a[permutedSparseVect[i]] >> 4;

                idx = permutedTable[dec] * (nByte64 + 1);

                int count = s * 2 + nByte64 * 8;
                for (int j = nByte64; j >= 0; --j)
                {
                    ulong tmp = BinaryPrimitives.ReadUInt64LittleEndian(resBytes[count..]);
                    BinaryPrimitives.WriteUInt64LittleEndian(resBytes[count..], tmp ^ table[idx + j]);
                    count -= 8;
                }
            }
#else
            ushort[] resByte16 = new ushort[res.Length * 4];
            for (int i = 0; i < weight; i++)
            {
                int dec = a[permutedSparseVect[i]] & 0xf;
                int s = a[permutedSparseVect[i]] >> 4;

                idx = permutedTable[dec] * (nByte64 + 1);

                int count = s;
                for (int j = 0; j <= nByte64; j++)
                {
                    Utils.XorULongToByte16Array(resByte16, count, table[idx + j]);
                    count += 4;
                }
            }
            Utils.FromByte16ArrayToULongArray(res, resByte16);
#endif
        }

        internal static void ModMult(ulong[] res, int[] a, ulong[] b, int weight,int n,  int nByte64, int we,
            HqcKeccakRandomGenerator random)
        {
            ulong[] tmp = new ulong[(nByte64 << 1) + 1];
            FastConvolutionMult(tmp, a, b, weight, nByte64, we, random);
            Mod(res, tmp, n, nByte64);
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
