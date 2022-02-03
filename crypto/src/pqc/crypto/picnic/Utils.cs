
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public class Utils
    {
        protected internal static void Fill(uint[] buf, int from, int to, uint b)
        {
            for (int i = from; i < to; ++i)
            {
                buf[i] = b;
            }
        }
        protected internal static int NumBytes(int numBits)
        {
            return (numBits == 0) ? 0 : ((numBits - 1) / 8 + 1);
        }

        protected internal static uint ceil_log2(uint x)
        {
            if (x == 0)
            {
                return 0;
            }

            return 32 - nlz(x - 1);
        }

        private static uint nlz(uint x)
        {
            uint n;

            if (x == 0) return (32);
            n = 1;
            if ((x >> 16) == 0)
            {
                n = n + 16;
                x = x << 16;
            }

            if ((x >> 24) == 0)
            {
                n = n + 8;
                x = x << 8;
            }

            if ((x >> 28) == 0)
            {
                n = n + 4;
                x = x << 4;
            }

            if ((x >> 30) == 0)
            {
                n = n + 2;
                x = x << 2;
            }

            n = (n - (x >> 31));

            return n;
        }


        protected static int Parity(byte[] data, int len)
        {
            byte x = data[0];

            for (int i = 1; i < len; i++)
            {
                x ^= data[i];
            }

            /* Compute parity of x using code from Section 5-2 of
             * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
             * http://www.hackersdelight.org/hdcodetxt/parity.c.txt
             */
            int y = x ^ (x >> 1);
            y ^= (y >> 2);
            y ^= (y >> 4);
            y ^= (y >> 8);
            y ^= (y >> 16);
            return y & 1;
        }

        protected internal static uint Parity16(uint x)
        {
            uint y = x ^ (x >> 1);

            y ^= (y >> 2);
            y ^= (y >> 4);
            y ^= (y >> 8);
            return y & 1;
        }

        protected internal static uint Parity32(uint x)
        {
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
        protected internal static void SetBitInWordArray(uint[] array, int bitNumber, uint val)
        {
            SetBit(array, bitNumber, (int)val);
        }

        /* Get one bit from a 32-bit int array */
        protected internal static uint GetBitFromWordArray(uint[] array, int bitNumber)
        {
            return GetBit(array, bitNumber);
        }

        /* Get one bit from a byte array */
        internal protected static byte GetBit(byte[] array, int bitNumber)
        {
            return (byte) ((array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01);
        }

        /* Get one bit from a byte array */
        internal protected static uint GetBit(uint[] array, int bitNumber)
        {
            uint temp = Pack.LE_To_UInt32(Pack.UInt32_To_BE(array[bitNumber / 32]), 0);
            return ((temp >> (31 - (bitNumber % 32))) & 0x01);
        }

        /* Set a specific bit in a int array to a given value */
        internal protected static void SetBit(uint[] bytes, int bitNumber, int val)
        {
            uint temp = Pack.LE_To_UInt32(Pack.UInt32_To_BE(bytes[bitNumber / 32]), 0);
            int x = (((int)temp & ~(1 << (31 - (bitNumber % 32)))) | (val << (31 - (bitNumber % 32))));
            bytes[bitNumber / 32] = Pack.LE_To_UInt32(Pack.UInt32_To_BE((uint)x), 0);
//        bytes[bitNumber / 32]  = ((bytes[bitNumber/4 >> 3]
//                        & ~(1 << (31 - (bitNumber % 32)))) | (val << (31 - (bitNumber % 32))));
        }

        internal protected static void SetBit(byte[] bytes, int bitNumber, byte val)
        {
            bytes[bitNumber / 8] = (byte) ((bytes[bitNumber >> 3]
                                            & ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8))));
        }
    }
}
