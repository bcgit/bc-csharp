using System;

namespace Org.BouncyCastle.Math.Raw
{
    internal abstract class Interleave
    {
        private const ulong M32 = 0x55555555UL;
        private const ulong M64 = 0x5555555555555555UL;
        private const ulong M64R = 0xAAAAAAAAAAAAAAAAUL;

        internal static uint Expand8to16(uint x)
        {
            x &= 0xFFU;
            x = (x | (x << 4)) & 0x0F0FU;
            x = (x | (x << 2)) & 0x3333U;
            x = (x | (x << 1)) & 0x5555U;
            return x;
        }

        internal static uint Expand16to32(uint x)
        {
            x &= 0xFFFFU;
            x = (x | (x << 8)) & 0x00FF00FFU;
            x = (x | (x << 4)) & 0x0F0F0F0FU;
            x = (x | (x << 2)) & 0x33333333U;
            x = (x | (x << 1)) & 0x55555555U;
            return x;
        }

        internal static ulong Expand32to64(uint x)
        {
            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);

            return ((x >> 1) & M32) << 32 | (x & M32);
        }

        internal static void Expand64To128(ulong x, ulong[] z, int zOff)
        {
            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);

            z[zOff    ] = (x     ) & M64;
            z[zOff + 1] = (x >> 1) & M64;
        }

        internal static void Expand64To128(ulong[] zs, int zsOff, int zsLen)
        {
            int i = zsLen, zsPos = zsOff + zsLen << 1;
            while (--i >= 0)
            {
                zsPos -= 2;
                Expand64To128(zs[zsOff + i], zs, zsPos);
            }
        }

        internal static void Expand64To128(ulong[] xs, int xsOff, int xsLen, ulong[] zs, int zsOff)
        {
            for (int i = 0; i < xsLen; ++i)
            {
                Expand64To128(xs[xsOff + i], zs, zsOff);
                zsOff += 2;
            }
        }

        internal static void Expand64To128Rev(ulong x, ulong[] z, int zOff)
        {
            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);

            z[zOff    ] = (x     ) & M64R;
            z[zOff + 1] = (x << 1) & M64R;
        }

        internal static uint Shuffle(uint x)
        {
            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);
            return x;
        }

        internal static ulong Shuffle(ulong x)
        {
            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);
            return x;
        }

        internal static uint Shuffle2(uint x)
        {
            // "shuffle" (twice) low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00AA00AAU, 7);
            x = Bits.BitPermuteStep(x, 0x0000CCCCU, 14);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            return x;
        }

        internal static uint Unshuffle(uint x)
        {
            // "unshuffle" even bits to low half and odd bits to high half
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            return x;
        }

        internal static ulong Unshuffle(ulong x)
        {
            // "unshuffle" even bits to low half and odd bits to high half
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            return x;
        }

        internal static uint Unshuffle2(uint x)
        {
            // "unshuffle" (twice) even bits to low half and odd bits to high half
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0000CCCCU, 14);
            x = Bits.BitPermuteStep(x, 0x00AA00AAU, 7);
            return x;
        }
    }
}
