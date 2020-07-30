using System;

namespace Org.BouncyCastle.Utilities
{
    public abstract class Integers
    {
        public static int NumberOfLeadingZeros(int i)
        {
            if (i <= 0)
                return (~i >> (31 - 5)) & (1 << 5);

            uint u = (uint)i;
            int n = 1;
            if (0 == (u >> 16)) { n += 16; u <<= 16; }
            if (0 == (u >> 24)) { n +=  8; u <<=  8; }
            if (0 == (u >> 28)) { n +=  4; u <<=  4; }
            if (0 == (u >> 30)) { n +=  2; u <<=  2; }
            n -= (int)(u >> 31);
            return n;
        }

        public static int NumberOfTrailingZeros(int i)
        {
            if (i == 0)
                return 32;

            int count = 0;
            while ((i & 1) == 0)
            {
                i >>= 1;
                ++count;
            }
            return count;
        }

        public static int RotateLeft(int i, int distance)
        {
            return (i << distance) ^ (int)((uint)i >> -distance);
        }

        [CLSCompliantAttribute(false)]
        public static uint RotateLeft(uint i, int distance)
        {
            return (i << distance) ^ (i >> -distance);
        }

        public static int RotateRight(int i, int distance)
        {
            return (int)((uint)i >> distance) ^ (i << -distance);
        }

        [CLSCompliantAttribute(false)]
        public static uint RotateRight(uint i, int distance)
        {
            return (i >> distance) ^ (i << -distance);
        }
    }
}
