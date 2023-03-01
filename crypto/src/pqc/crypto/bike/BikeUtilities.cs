using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal class BikeUtilities
    {
        internal static int GetHammingWeight(byte[] bytes)
        {
            int hammingWeight = 0;
            for (int i = 0; i < bytes.Length; i++)
            {
                hammingWeight += bytes[i];
            }
            return hammingWeight;
        }

        internal static void FromByteArrayToBitArray(byte[] output, byte[] input)
        {
            int max = (output.Length / 8);
            for (int i = 0; i < max; i++)
            {
                for (int j = 0; j != 8; j++)
                {
                    output[i * 8 + j] = (byte)((input[i] >> j) & 1);
                }
            }
            if (output.Length % 8 != 0)
            {
                int off = max * 8;
                int count = 0;
                while (off < output.Length)
                {
                    output[off++] = (byte)((input[max] >> count) & 1);
                    count++;
                }
            }
        }

        internal static void FromBitArrayToByteArray(byte[] output, byte[] input, int inputOff, int inputLen)
        {
            int count = 0;
            int pos = 0;
            while (count < inputLen)
            {
                if (count + 8 >= inputLen)
                {// last set of bits cannot have enough 8 bits
                    int b = input[inputOff + count];
                    for (int j = inputLen - count - 1; j >= 1; j--)
                    { //bin in reversed order
                        b |= input[inputOff + count + j] << j;
                    }
                    output[pos] = (byte)b;
                }
                else
                {
                    int b = input[inputOff + count];
                    for (int j = 7; j >= 1; j--)
                    { //bin in reversed order
                        b |= input[inputOff + count + j] << j;
                    }
                    output[pos] = (byte)b;
                }

                count += 8;
                pos++;
            }
        }

        internal static void GenerateRandomByteArray(byte[] res, int size, int weight, IXof digest)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[4];
#else
            byte[] buf = new byte[4];
#endif

            for (int i = weight - 1; i >= 0; i--)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                digest.Output(buf);
                ulong temp = Pack.LE_To_UInt32(buf);
#else
                digest.Output(buf, 0, 4);
                ulong temp = Pack.LE_To_UInt32(buf, 0);
#endif

                temp *= (uint)(size - i);
                uint rand_pos = (uint)i + (uint)(temp >> 32);

                if (CheckBit(res, rand_pos) != 0)
                {
                    rand_pos = (uint)i;
                }
                SetBit(res, rand_pos);
            }
        }

        private static uint CheckBit(byte[] tmp, uint position)
        {
            uint index = position / 8;
            uint pos = position % 8;
            return ((uint)tmp[index] >> (int)pos) & 1U;
        }

        private static void SetBit(byte[] tmp, uint position)
        {
            uint index = position / 8;
            uint pos = position % 8;
            tmp[index] |= (byte)(1 << (int)pos);
        }
    }
}
