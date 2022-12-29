#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal static class PicnicUtilities
    {
        internal static void Fill(uint[] buf, int from, int to, uint b)
        {
            for (int i = from; i < to; ++i)
            {
                buf[i] = b;
            }
        }
        internal static int NumBytes(int numBits)
        {
            return (numBits + 7) >> 3;
        }

        internal static uint ceil_log2(uint x)
        {
            return x == 0 ? 0 : 32 - (uint)Integers.NumberOfLeadingZeros((int)(x - 1));
        }

        internal static int Parity(byte[] data, int len)
        {
            byte x = data[0];

            for (int i = 1; i < len; i++)
            {
                x ^= data[i];
            }

            return (int)Parity16(x);
        }

        internal static uint Parity16(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Popcnt.IsSupported)
            {
                return Popcnt.PopCount(x & 0xFFFF) & 1U;
            }
#endif

            uint y = x ^ (x >> 1);

            y ^= (y >> 2);
            y ^= (y >> 4);
            y ^= (y >> 8);
            return y & 1;
        }

        internal static uint Parity32(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Popcnt.IsSupported)
            {
                return Popcnt.PopCount(x) & 1U;
            }
#endif

            /* Compute parity of x using code from Section 5-2 of
             * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
             * http://www.hackersdelight.org/hdcodetxt/parity.c.txt
             */
            uint y = (x ^ (x >> 1));
            y ^= (y >> 2);
            y ^= (y >> 4);
            y ^= (y >> 8);
            y ^= (y >> 16);
            return (y & 1);
        }


        /* Set a specific bit in a byte array to a given value */
        internal static void SetBitInWordArray(uint[] array, int bitNumber, uint val)
        {
            SetBit(array, bitNumber, val);
        }

        /* Get one bit from a 32-bit int array */
        internal static uint GetBitFromWordArray(uint[] array, int bitNumber)
        {
            return GetBit(array, bitNumber);
        }

        /* Get one bit from a byte array */
        internal static byte GetBit(byte[] array, int bitNumber)
        {
            int arrayPos = bitNumber >> 3, bitPos = (bitNumber & 7) ^ 7;
            return (byte)((array[arrayPos] >> bitPos) & 1);
        }

        internal static uint GetBit(uint word, int bitNumber)
        {
            int bitPos = bitNumber ^ 7;
            return (word >> bitPos) & 1U;
        }

        /* Get one bit from a byte array */
        internal static uint GetBit(uint[] array, int bitNumber)
        {
            int arrayPos = bitNumber >> 5, bitPos = (bitNumber & 31) ^ 7;
            return (array[arrayPos] >> bitPos) & 1;
        }

        internal static void SetBit(byte[] array, int bitNumber, byte val)
        {
            int arrayPos = bitNumber >> 3, bitPos = (bitNumber & 7) ^ 7;
            uint t = array[arrayPos];
            t &= ~(1U << bitPos);
            t |= (uint)val << bitPos;
            array[arrayPos] = (byte)t;
        }

        internal static uint SetBit(uint word, int bitNumber, uint bit)
        {
            int bitPos = bitNumber ^ 7;
            word &= ~(1U << bitPos);
            word |= bit << bitPos;
            return word;
        }

        /* Set a specific bit in a int array to a given value */
        internal static void SetBit(uint[] array, int bitNumber, uint val)
        {
            int arrayPos = bitNumber >> 5, bitPos = (bitNumber & 31) ^ 7;
            uint t = array[arrayPos];
            t &= ~(1U << bitPos);
            t |= val << bitPos;
            array[arrayPos] = t;
        }

        internal static void ZeroTrailingBits(byte[] data, int bitLength)
        {
            int partial = bitLength & 7;
            if (partial != 0)
            {
                data[bitLength >> 3] &= (byte)(0xFF00 >> partial);
            }
        }
    }
}
