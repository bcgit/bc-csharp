using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;

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

        internal static void FromBitsToUlongs(ulong[] output, byte[] input, int inputOff, int inputLen)
        {
            for (int i = 0; i < inputLen; ++i)
            {
                ulong bit = input[inputOff + i] & 1UL;
                output[i >> 6] |= bit << (i & 63);
            }
        }

        internal static void GenerateRandomUlongs(ulong[] res, int size, int weight, IXof digest)
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

                if (CheckBit(res, rand_pos))
                {
                    rand_pos = (uint)i;
                }
                SetBit(res, rand_pos);
            }
        }

        private static bool CheckBit(ulong[] tmp, uint position)
        {
            uint index = position >> 6;
            uint pos = position & 63;
            return ((tmp[index] >> (int)pos) & 1UL) != 0UL;
        }

        private static void SetBit(ulong[] tmp, uint position)
        {
            uint index = position >> 6;
            uint pos = position & 63;
            tmp[index] |= 1UL << (int)pos;
        }
    }
}
