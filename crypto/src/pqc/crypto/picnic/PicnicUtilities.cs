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

            return Integers.PopCount(x) & 1;
        }

        internal static uint Parity16(uint x)
        {
            return (uint)(Integers.PopCount(x & 0xFFFF) & 1);
        }

        internal static uint Parity32(uint x)
        {
            return (uint)(Integers.PopCount(x) & 1);
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

        /* Get a crumb (i.e. two bits) from a byte array. */
        internal static byte GetCrumbAligned(byte[] array, int crumbNumber)
        {
            int arrayPos = crumbNumber >> 2, bitPos = ((crumbNumber << 1) & 6) ^ 6;
            uint b = (uint)array[arrayPos] >> bitPos;
            return (byte)((b & 1) << 1 | (b & 2) >> 1);
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

        internal static void ZeroTrailingBits(uint[] data, int bitLength)
        {
            int partialWord = bitLength & 31;
            if (partialWord != 0)
            {
                data[bitLength >> 5] &= GetTrailingBitsMask(bitLength);
            }
        }

        internal static uint GetTrailingBitsMask(int bitLength)
        {
            int partialShift = bitLength & ~7;
            uint mask = ~(0xFFFFFFFFU << partialShift);

            int partialByte = bitLength & 7;
            if (partialByte != 0)
            {
                mask ^= ((0xFF00U >> partialByte) & 0xFFU) << partialShift;
            }

            return mask;
        }
    }
}
