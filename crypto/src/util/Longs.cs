using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Numerics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Utilities
{
    /// <summary>Utility methods and constants for working with 64-bit integers.</summary>
    public static class Longs
    {
        /// <summary>The <c>NumBits</c> constant, with the value <c>64</c>.</summary>
        public const int NumBits = 64;
        /// <summary>The <c>NumBytes</c> constant, with the value <c>8</c>.</summary>
        public const int NumBytes = 8;

#if !NETCOREAPP3_0_OR_GREATER
        private static readonly byte[] DeBruijnTZ = {
            0x3F, 0x00, 0x01, 0x34, 0x02, 0x06, 0x35, 0x1A, 0x03, 0x25, 0x28, 0x07, 0x21, 0x36, 0x2F, 0x1B,
            0x3D, 0x04, 0x26, 0x2D, 0x2B, 0x29, 0x15, 0x08, 0x17, 0x22, 0x3A, 0x37, 0x30, 0x11, 0x1C, 0x0A,
            0x3E, 0x33, 0x05, 0x19, 0x24, 0x27, 0x20, 0x2E, 0x3C, 0x2C, 0x2A, 0x14, 0x16, 0x39, 0x10, 0x09,
            0x32, 0x18, 0x23, 0x1F, 0x3B, 0x13, 0x38, 0x0F, 0x31, 0x1E, 0x12, 0x0E, 0x1D, 0x0D, 0x0C, 0x0B };
#endif

        /// <summary>Get the number of bits required to represent a value, not including the sign bit.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The bit length of the value.</returns>
        public static int BitLength(long i) => NumBits - NumberOfLeadingZeros(i);

        /// <summary>Get the number of bits required to represent a value, not including the sign bit.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The bit length of the value.</returns>
        [CLSCompliant(false)]
        public static int BitLength(ulong u) => BitLength((long)u);

        /// <summary>Compare two values numerically (for <c>CompareUnsigned</c>, as unsigned numbers).</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>
        /// A negative number if <paramref name="x"/> is smaller, zero if they are equal, a positive number if <paramref
        /// name="x"/> is larger.
        /// </returns>
        public static int Compare(long x, long y) => x.CompareTo(y);

        /// <summary>Compare two values numerically (for <c>CompareUnsigned</c>, as unsigned numbers).</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>
        /// A negative number if <paramref name="x"/> is smaller, zero if they are equal, a positive number if <paramref
        /// name="x"/> is larger.
        /// </returns>
        [CLSCompliant(false)]
        public static int Compare(ulong x, ulong y) => x.CompareTo(y);

        /// <summary>Compare two values numerically (for <c>CompareUnsigned</c>, as unsigned numbers).</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>
        /// A negative number if <paramref name="x"/> is smaller, zero if they are equal, a positive number if <paramref
        /// name="x"/> is larger.
        /// </returns>
        public static int CompareUnsigned(long x, long y) => Compare((ulong)x, (ulong)y);

        /// <summary>
        /// Get a value with a single set bit, at the position of the highest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its highest one-bit set, or zero if the argument is zero.</returns>
        public static long HighestOneBit(long i) => (long)HighestOneBit((ulong)i);

        /// <summary>
        /// Get a value with a single set bit, at the position of the highest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its highest one-bit set, or zero if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static ulong HighestOneBit(ulong i)
        {
            i |= i >>  1;
            i |= i >>  2;
            i |= i >>  4;
            i |= i >>  8;
            i |= i >> 16;
            i |= i >> 32;
            return i - (i >> 1);
        }

        /// <summary>
        /// Get a value with a single set bit, at the position of the lowest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its lowest one-bit set, or zero if the argument is zero.</returns>
        public static long LowestOneBit(long i) => i & -i;

        /// <summary>
        /// Get a value with a single set bit, at the position of the lowest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its lowest one-bit set, or zero if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static ulong LowestOneBit(ulong i) => (ulong)LowestOneBit((long)i);

        /// <summary>Count the zero bits above the highest-order set bit.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The number of leading zero bits, or the total bit count if the argument is zero.</returns>
        public static int NumberOfLeadingZeros(long i)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.LeadingZeroCount((ulong)i);
#else
            int x = (int)(i >> 32), n = 0;
            if (x == 0)
            {
                n = 32;
                x = (int)i;
            }
            return n + Integers.NumberOfLeadingZeros(x);
#endif
        }

        /// <summary>Count the zero bits above the highest-order set bit.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The number of leading zero bits, or the total bit count if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static int NumberOfLeadingZeros(ulong u) => NumberOfLeadingZeros((long)u);

        /// <summary>Count the zero bits below the lowest-order set bit.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The number of trailing zero bits, or the total bit count if the argument is zero.</returns>
        public static int NumberOfTrailingZeros(long i)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.TrailingZeroCount((ulong)i);
#else
            int n = DeBruijnTZ[(uint)((ulong)((i & -i) * 0x045FBAC7992A70DAL) >> 58)];
            long m = (((i & 0xFFFFFFFFL) | (long)((ulong)i >> 32)) - 1L) >> 63;
            return n - (int)m;
#endif
        }

        /// <summary>Count the zero bits below the lowest-order set bit.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The number of trailing zero bits, or the total bit count if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static int NumberOfTrailingZeros(ulong u) => NumberOfTrailingZeros((long)u);

        /// <summary>Count the bits that are set.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The number of one-bits.</returns>
        public static int PopCount(long i) => PopCount((ulong)i);

        /// <summary>Count the bits that are set.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The number of one-bits.</returns>
        [CLSCompliant(false)]
        public static int PopCount(ulong u)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.PopCount(u);
#else
            return Integers.PopCount((uint)u)
                +  Integers.PopCount((uint)(u >> 32));
#endif
        }

        /// <summary>Reverse the order of the bits of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bits in reverse order.</returns>
        public static long Reverse(long i) => (long)Reverse((ulong)i);

        /// <summary>Reverse the order of the bits of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bits in reverse order.</returns>
        [CLSCompliant(false)]
        public static ulong Reverse(ulong i)
        {
            i = Bits.BitPermuteStepSimple(i, 0x5555555555555555UL, 1);
            i = Bits.BitPermuteStepSimple(i, 0x3333333333333333UL, 2);
            i = Bits.BitPermuteStepSimple(i, 0x0F0F0F0F0F0F0F0FUL, 4);
            return ReverseBytes(i);
        }

        /// <summary>Reverse the order of the bytes of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bytes in reverse order.</returns>
        public static long ReverseBytes(long i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return (long)ReverseBytes((ulong)i);
#endif
        }

        /// <summary>Reverse the order of the bytes of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bytes in reverse order.</returns>
        [CLSCompliant(false)]
        public static ulong ReverseBytes(ulong i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i & 0xFF000000FF000000UL,  8) |
                   RotateLeft(i & 0x00FF000000FF0000UL, 24) |
                   RotateLeft(i & 0x0000FF000000FF00UL, 40) |
                   RotateLeft(i & 0x000000FF000000FFUL, 56);
#endif
        }

        /// <summary>Rotate the bits of a value to the left.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        public static long RotateLeft(long i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return (long)BitOperations.RotateLeft((ulong)i, distance);
#else
            return (i << distance) | (long)((ulong)i >> -distance);
#endif
        }

        /// <summary>Rotate the bits of a value to the left.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        [CLSCompliant(false)]
        public static ulong RotateLeft(ulong i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.RotateLeft(i, distance);
#else
            return (i << distance) | (i >> -distance);
#endif
        }

        /// <summary>Rotate the bits of a value to the right.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        public static long RotateRight(long i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return (long)BitOperations.RotateRight((ulong)i, distance);
#else
            return (long)((ulong)i >> distance) | (i << -distance);
#endif
        }

        /// <summary>Rotate the bits of a value to the right.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        [CLSCompliant(false)]
        public static ulong RotateRight(ulong i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.RotateRight(i, distance);
#else
            return (i >> distance) | (i << -distance);
#endif
        }
    }
}
