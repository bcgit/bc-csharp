﻿using System;
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
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
            Expand64To128(x, z.AsSpan(zOff));
        }

        internal static void Expand64To128(ulong x, Span<ulong> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
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

        internal static void Expand64To128(ulong[] xs, int xsOff, int xsLen, ulong[] zs, int zsOff)
        {
            Expand64To128(xs.AsSpan(xsOff, xsLen), zs.AsSpan(zsOff));
        }

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

        internal static ulong Expand64To128Rev(ulong x, out ulong low)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
            {
                return Bmi2.ParallelBitDeposit(x >> 24, 0x88888888U)
                    |  Bmi2.ParallelBitDeposit(x >> 16, 0x44444444U)
                    |  Bmi2.ParallelBitDeposit(x >>  8, 0x22222222U)
                    |  Bmi2.ParallelBitDeposit(x      , 0x11111111U);
            }
#endif

            // 4 3 2 1 0 => 2 1 4 3 0
            x = Bits.BitPermuteStep(x, 0x0000F0F0U, 12);
            x = Bits.BitPermuteStep(x, 0x00CC00CCU, 6);

            // 2 1 4 3 0 => 2 1 4 0 3
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);

            // 2 1 4 0 3 => 2 1 0 4 3
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);

            return x;
        }

        internal static ulong Shuffle2(ulong x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
            {
                return Bmi2.X64.ParallelBitDeposit(x >> 48, 0x8888888888888888UL)
                    |  Bmi2.X64.ParallelBitDeposit(x >> 32, 0x4444444444444444UL)
                    |  Bmi2.X64.ParallelBitDeposit(x >> 16, 0x2222222222222222UL)
                    |  Bmi2.X64.ParallelBitDeposit(x      , 0x1111111111111111UL);
            }
#endif

            // 5 4 3 2 1 0 => 3 2 5 4 1 0
            x = Bits.BitPermuteStep(x, 0x00000000FF00FF00UL, 24);
            x = Bits.BitPermuteStep(x, 0x0000F0F00000F0F0UL, 12);

            // 3 2 5 4 1 0 => 3 2 1 0 5 4
            x = Bits.BitPermuteStep(x, 0x00CC00CC00CC00CCUL, 6);
            x = Bits.BitPermuteStep(x, 0x0A0A0A0A0A0A0A0AUL, 3);

            return x;
        }

        internal static uint Unshuffle(uint x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
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
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.IsEnabled)
            {
                return Bmi2.ParallelBitExtract(x, 0x88888888U) << 24
                    |  Bmi2.ParallelBitExtract(x, 0x44444444U) << 16
                    |  Bmi2.ParallelBitExtract(x, 0x22222222U) <<  8
                    |  Bmi2.ParallelBitExtract(x, 0x11111111U);
            }
#endif

            // 4 3 2 1 0 => 4 3 1 2 0
            x = Bits.BitPermuteStep(x, 0x0C0C0C0CU, 2);

            // 4 3 1 2 0 => 4 3 1 0 2
            x = Bits.BitPermuteStep(x, 0x22222222U, 1);

            // 4 3 1 0 2 => 1 0 4 3 2
            x = Bits.BitPermuteStep(x, 0x0000F0F0U, 12);
            x = Bits.BitPermuteStep(x, 0x00CC00CCU, 6);

            return x;
        }

        internal static ulong Unshuffle2(ulong x)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled)
            {
                return Bmi2.X64.ParallelBitExtract(x, 0x8888888888888888UL) << 48
                    |  Bmi2.X64.ParallelBitExtract(x, 0x4444444444444444UL) << 32
                    |  Bmi2.X64.ParallelBitExtract(x, 0x2222222222222222UL) << 16
                    |  Bmi2.X64.ParallelBitExtract(x, 0x1111111111111111UL);
            }
#endif

            // 5 4 3 2 1 0 => 5 4 1 0 3 2
            x = Bits.BitPermuteStep(x, 0x00CC00CC00CC00CCUL, 6);
            x = Bits.BitPermuteStep(x, 0x0A0A0A0A0A0A0A0AUL, 3);

            // 5 4 1 0 3 2 => 1 0 5 4 3 2
            x = Bits.BitPermuteStep(x, 0x00000000FF00FF00UL, 24);
            x = Bits.BitPermuteStep(x, 0x0000F0F00000F0F0UL, 12);

            return x;
        }

        internal static ulong Transpose(ulong x)
        {
            x = Bits.BitPermuteStep(x, 0x00000000F0F0F0F0UL, 28);
            x = Bits.BitPermuteStep(x, 0x0000CCCC0000CCCCUL, 14);
            x = Bits.BitPermuteStep(x, 0x00AA00AA00AA00AAUL, 7);
            return x;
        }
    }
}
