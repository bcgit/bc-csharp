using System;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Utilities
{
    public abstract class Integers
    {
        public const int NumBits = 32;
        public const int NumBytes = 4;

        private static readonly byte[] DeBruijnTZ = {
            0x1F, 0x00, 0x1B, 0x01, 0x1C, 0x0D, 0x17, 0x02, 0x1D, 0x15, 0x13, 0x0E, 0x18, 0x10, 0x03, 0x07,
            0x1E, 0x1A, 0x0C, 0x16, 0x14, 0x12, 0x0F, 0x06, 0x19, 0x0B, 0x11, 0x05, 0x0A, 0x04, 0x09, 0x08 };

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
            int n = DeBruijnTZ[(uint)((i & -i) * 0x0EF96A62) >> 27];
            int m = (((i & 0xFFFF) | (int)((uint)i >> 16)) - 1) >> 31;
            return n - m;
        }

        public static int Reverse(int i)
        {
            return (int)Reverse((uint)i);
        }

        [CLSCompliantAttribute(false)]
        public static uint Reverse(uint i)
        {
            i = Bits.BitPermuteStepSimple(i, 0x55555555U, 1);
            i = Bits.BitPermuteStepSimple(i, 0x33333333U, 2);
            i = Bits.BitPermuteStepSimple(i, 0x0F0F0F0FU, 4);
            return ReverseBytes(i);
        }

        public static int ReverseBytes(int i)
        {
            return (int)ReverseBytes((uint)i);
        }

        [CLSCompliantAttribute(false)]
        public static uint ReverseBytes(uint i)
        {
            return RotateLeft(i & 0xFF00FF00U,  8) |
                   RotateLeft(i & 0x00FF00FFU, 24);
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
