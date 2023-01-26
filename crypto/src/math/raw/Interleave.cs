using System;
using System.Diagnostics;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

namespace Org.BouncyCastle.Math.Raw
{
    internal static class Interleave
    {
        private const ulong M32 = 0x55555555UL;
        private const ulong M64 = 0x5555555555555555UL;
        private const ulong M64R = 0xAAAAAAAAAAAAAAAAUL;

        internal static uint Expand8to16(byte x)
        {
            uint t = x;

#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.ParallelBitDeposit(t, 0x55555555U);
            }
#endif
            t = (t | (t << 4)) & 0x0F0FU;
            t = (t | (t << 2)) & 0x3333U;
            t = (t | (t << 1)) & 0x5555U;
            return t;
        }

        internal static uint Expand16to32(ushort x)
        {
            uint t = x;

#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.ParallelBitDeposit(t, 0x55555555U);
            }
#endif
            t = (t | (t << 8)) & 0x00FF00FFU;
            t = (t | (t << 4)) & 0x0F0F0F0FU;
            t = (t | (t << 2)) & 0x33333333U;
            t = (t | (t << 1)) & 0x55555555U;
            return t;
        }

        internal static ulong Expand32to64(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return (ulong)Bmi2.ParallelBitDeposit(x >> 16, 0x55555555U) << 32
                    |         Bmi2.ParallelBitDeposit(x      , 0x55555555U);
            }
#endif

            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);

            return ((x >> 1) & M32) << 32 | (x & M32);
        }

        internal static void Expand64To128(ulong x, ulong[] z, int zOff)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                z[zOff    ] = Bmi2.X64.ParallelBitDeposit(x      , 0x5555555555555555UL);
                z[zOff + 1] = Bmi2.X64.ParallelBitDeposit(x >> 32, 0x5555555555555555UL);
                return;
            }
#endif

            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);

            z[zOff    ] = (x     ) & M64;
            z[zOff + 1] = (x >> 1) & M64;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Expand64To128(ulong x, Span<ulong> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                z[0] = Bmi2.X64.ParallelBitDeposit(x      , 0x5555555555555555UL);
                z[1] = Bmi2.X64.ParallelBitDeposit(x >> 32, 0x5555555555555555UL);
                return;
            }
#endif

            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);

            z[0] = (x     ) & M64;
            z[1] = (x >> 1) & M64;
        }
#endif

        internal static void Expand64To128(ulong[] xs, int xsOff, int xsLen, ulong[] zs, int zsOff)
        {
            int xsPos = xsLen, zsPos = zsOff + (xsLen << 1);
            while (--xsPos >= 0)
            {
                zsPos -= 2;
                Expand64To128(xs[xsOff + xsPos], zs, zsPos);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Expand64To128(ReadOnlySpan<ulong> xs, Span<ulong> zs)
        {
            int xsPos = xs.Length, zsPos = xs.Length << 1;
            Debug.Assert(!zs[xsPos..zsPos].Overlaps(xs));
            while (--xsPos >= 0)
            {
                zsPos -= 2;
                Expand64To128(xs[xsPos], zs[zsPos..]);
            }
        }
#endif

        internal static ulong Expand64To128Rev(ulong x, out ulong low)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                low  = Bmi2.X64.ParallelBitDeposit(x >> 32, 0xAAAAAAAAAAAAAAAAUL);
                return Bmi2.X64.ParallelBitDeposit(x      , 0xAAAAAAAAAAAAAAAAUL);
            }
#endif

            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);

            low  = (x     ) & M64R;
            return (x << 1) & M64R;
        }

        internal static uint Shuffle(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.ParallelBitDeposit(x >> 16, 0xAAAAAAAAU)
                    |  Bmi2.ParallelBitDeposit(x      , 0x55555555U);
            }
#endif

            // "shuffle" low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);
            return x;
        }

        internal static ulong Shuffle(ulong x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.X64.ParallelBitDeposit(x >> 32, 0xAAAAAAAAAAAAAAAAUL)
                    |  Bmi2.X64.ParallelBitDeposit(x      , 0x5555555555555555UL);
            }
#endif

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
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.ParallelBitDeposit(x >> 24, 0x88888888U)
                    |  Bmi2.ParallelBitDeposit(x >> 16, 0x44444444U)
                    |  Bmi2.ParallelBitDeposit(x >>  8, 0x22222222U)
                    |  Bmi2.ParallelBitDeposit(x      , 0x11111111U);
            }
#endif

            // "shuffle" (twice) low half to even bits and high half to odd bits
            x = Bits.BitPermuteStep(x, 0x00AA00AAU, 7);
            x = Bits.BitPermuteStep(x, 0x0000CCCCU, 14);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            return x;
        }

        internal static uint Unshuffle(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.ParallelBitExtract(x, 0xAAAAAAAAU) << 16
                    |  Bmi2.ParallelBitExtract(x, 0x55555555U);
            }
#endif

            // "unshuffle" even bits to low half and odd bits to high half
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            return x;
        }

        internal static ulong Unshuffle(ulong x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                return Bmi2.X64.ParallelBitExtract(x, 0xAAAAAAAAAAAAAAAAUL) << 32
                    |  Bmi2.X64.ParallelBitExtract(x, 0x5555555555555555UL);
            }
#endif

            // "unshuffle" even bits to low half and odd bits to high half
            x = Bits.BitPermuteStep(x, 0x2222222222222222UL, 1);
            x = Bits.BitPermuteStep(x, 0x0C0C0C0C0C0C0C0CUL, 2);
            x = Bits.BitPermuteStep(x, 0x00F000F000F000F0UL, 4);
            x = Bits.BitPermuteStep(x, 0x0000FF000000FF00UL, 8);
            x = Bits.BitPermuteStep(x, 0x00000000FFFF0000UL, 16);
            return x;
        }

        internal static ulong Unshuffle(ulong x, out ulong even)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                even = Bmi2.X64.ParallelBitExtract(x, 0x5555555555555555UL);
                return Bmi2.X64.ParallelBitExtract(x, 0xAAAAAAAAAAAAAAAAUL);
            }
#endif

            ulong u0 = Unshuffle(x);
            even = u0 & 0x00000000FFFFFFFFUL;
            return u0 >> 32;
        }

        internal static ulong Unshuffle(ulong x0, ulong x1, out ulong even)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                even = Bmi2.X64.ParallelBitExtract(x0, 0x5555555555555555UL)
                    |  Bmi2.X64.ParallelBitExtract(x1, 0x5555555555555555UL) << 32;
                return Bmi2.X64.ParallelBitExtract(x0, 0xAAAAAAAAAAAAAAAAUL)
                    |  Bmi2.X64.ParallelBitExtract(x1, 0xAAAAAAAAAAAAAAAAUL) << 32;
            }
#endif

            ulong u0 = Unshuffle(x0);
            ulong u1 = Unshuffle(x1);
            even = (u1 << 32) | (u0 & 0x00000000FFFFFFFFUL);
            return (u0 >> 32) | (u1 & 0xFFFFFFFF00000000UL);
        }

        internal static uint Unshuffle2(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.IsSupported)
            {
                return Bmi2.ParallelBitExtract(x, 0x88888888U) << 24
                    |  Bmi2.ParallelBitExtract(x, 0x44444444U) << 16
                    |  Bmi2.ParallelBitExtract(x, 0x22222222U) <<  8
                    |  Bmi2.ParallelBitExtract(x, 0x11111111U);
            }
#endif

            // "unshuffle" (twice) even bits to low half and odd bits to high half
            x = Bits.BitPermuteStep(x, 0x0000FF00U, 8);
            x = Bits.BitPermuteStep(x, 0x00F000F0U, 4);
            x = Bits.BitPermuteStep(x, 0x0000CCCCU, 14);
            x = Bits.BitPermuteStep(x, 0x00AA00AAU, 7);
            return x;
        }
    }
}
