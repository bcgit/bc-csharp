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
    /// <summary>Utility methods and constants for working with 32-bit integers.</summary>
    public static class Integers
    {
        /// <summary>The <c>NumBits</c> constant, with the value <c>32</c>.</summary>
        public const int NumBits = 32;
        /// <summary>The <c>NumBytes</c> constant, with the value <c>4</c>.</summary>
        public const int NumBytes = 4;

#if !NETCOREAPP3_0_OR_GREATER
        private static readonly byte[] DeBruijnTZ = {
            0x1F, 0x00, 0x1B, 0x01, 0x1C, 0x0D, 0x17, 0x02, 0x1D, 0x15, 0x13, 0x0E, 0x18, 0x10, 0x03, 0x07,
            0x1E, 0x1A, 0x0C, 0x16, 0x14, 0x12, 0x0F, 0x06, 0x19, 0x0B, 0x11, 0x05, 0x0A, 0x04, 0x09, 0x08 };
#endif

        /// <summary>Get the number of bits required to represent a value, not including the sign bit.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The bit length of the value.</returns>
        public static int BitLength(int i) => NumBits - NumberOfLeadingZeros(i);

        /// <summary>Get the number of bits required to represent a value, not including the sign bit.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The bit length of the value.</returns>
        [CLSCompliant(false)]
        public static int BitLength(uint u) => BitLength((int)u);

        /// <summary>Compare two values numerically (for <c>CompareUnsigned</c>, as unsigned numbers).</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>
        /// A negative number if <paramref name="x"/> is smaller, zero if they are equal, a positive number if <paramref
        /// name="x"/> is larger.
        /// </returns>
        public static int Compare(int x, int y) => x.CompareTo(y);

        /// <summary>Compare two values numerically (for <c>CompareUnsigned</c>, as unsigned numbers).</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>
        /// A negative number if <paramref name="x"/> is smaller, zero if they are equal, a positive number if <paramref
        /// name="x"/> is larger.
        /// </returns>
        [CLSCompliant(false)]
        public static int Compare(uint x, uint y) => x.CompareTo(y);

        /// <summary>Compare two values numerically (for <c>CompareUnsigned</c>, as unsigned numbers).</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>
        /// A negative number if <paramref name="x"/> is smaller, zero if they are equal, a positive number if <paramref
        /// name="x"/> is larger.
        /// </returns>
        public static int CompareUnsigned(int x, int y) => Compare((uint)x, (uint)y);

        /// <summary>
        /// Get a value with a single set bit, at the position of the highest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its highest one-bit set, or zero if the argument is zero.</returns>
        public static int HighestOneBit(int i) => (int)HighestOneBit((uint)i);

        /// <summary>
        /// Get a value with a single set bit, at the position of the highest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its highest one-bit set, or zero if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static uint HighestOneBit(uint i)
        {
            i |= i >>  1;
            i |= i >>  2;
            i |= i >>  4;
            i |= i >>  8;
            i |= i >> 16;
            return i - (i >> 1);
        }

        /// <summary>
        /// Get a value with a single set bit, at the position of the lowest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its lowest one-bit set, or zero if the argument is zero.</returns>
        public static int LowestOneBit(int i) => i & -i;

        /// <summary>
        /// Get a value with a single set bit, at the position of the lowest-order set bit of the argument.
        /// </summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with only its lowest one-bit set, or zero if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static uint LowestOneBit(uint i) => (uint)LowestOneBit((int)i);

        /// <summary>Count the zero bits above the highest-order set bit.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The number of leading zero bits, or the total bit count if the argument is zero.</returns>
        public static int NumberOfLeadingZeros(int i)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.LeadingZeroCount((uint)i);
#else
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
#endif
        }

        /// <summary>Count the zero bits above the highest-order set bit.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The number of leading zero bits, or the total bit count if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static int NumberOfLeadingZeros(uint u) => NumberOfLeadingZeros((int)u);

        /// <summary>Count the zero bits below the lowest-order set bit.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The number of trailing zero bits, or the total bit count if the argument is zero.</returns>
        public static int NumberOfTrailingZeros(int i)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.TrailingZeroCount(i);
#else
            int n = DeBruijnTZ[(uint)((i & -i) * 0x0EF96A62) >> 27];
            int m = (int)Nat.CZero((uint)i);
            return n - m;
#endif
        }

        /// <summary>Count the zero bits below the lowest-order set bit.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The number of trailing zero bits, or the total bit count if the argument is zero.</returns>
        [CLSCompliant(false)]
        public static int NumberOfTrailingZeros(uint u) => NumberOfTrailingZeros((int)u);

        /// <summary>Count the bits that are set.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The number of one-bits.</returns>
        public static int PopCount(int i) => PopCount((uint)i);

        /// <summary>Count the bits that are set.</summary>
        /// <param name="u">The value.</param>
        /// <returns>The number of one-bits.</returns>
        [CLSCompliant(false)]
        public static int PopCount(uint u)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.PopCount(u);
#else
            u -= (u >> 1) & 0x55555555;
            u = (u & 0x33333333) + ((u >> 2) & 0x33333333);
            u = (u + (u >> 4)) & 0x0f0f0f0f;
            u += (u >> 8);
            u += (u >> 16);
            u &= 0x3f;
            return (int)u;
#endif
        }

        /// <summary>Reverse the order of the bits of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bits in reverse order.</returns>
        public static int Reverse(int i) => (int)Reverse((uint)i);

        /// <summary>Reverse the order of the bits of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bits in reverse order.</returns>
        [CLSCompliant(false)]
        public static uint Reverse(uint i)
        {
            i = Bits.BitPermuteStepSimple(i, 0x55555555U, 1);
            i = Bits.BitPermuteStepSimple(i, 0x33333333U, 2);
            i = Bits.BitPermuteStepSimple(i, 0x0F0F0F0FU, 4);
            return ReverseBytes(i);
        }

        /// <summary>Reverse the order of the bytes of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bytes in reverse order.</returns>
        public static int ReverseBytes(int i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return (int)ReverseBytes((uint)i);
#endif
        }

        /// <summary>Reverse the order of the bytes of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bytes in reverse order.</returns>
        [CLSCompliant(false)]
        public static uint ReverseBytes(uint i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i & 0xFF00FF00U,  8) |
                   RotateLeft(i & 0x00FF00FFU, 24);
#endif
        }

        /// <summary>Rotate the bits of a value to the left.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        public static int RotateLeft(int i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return (int)BitOperations.RotateLeft((uint)i, distance);
#else
            return (i << distance) | (int)((uint)i >> -distance);
#endif
        }

        /// <summary>Rotate the bits of a value to the left.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        [CLSCompliant(false)]
        public static uint RotateLeft(uint i, int distance)
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
        public static int RotateRight(int i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return (int)BitOperations.RotateRight((uint)i, distance);
#else
            return (int)((uint)i >> distance) | (i << -distance);
#endif
        }

        /// <summary>Rotate the bits of a value to the right.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        [CLSCompliant(false)]
        public static uint RotateRight(uint i, int distance)
        {
#if NETCOREAPP3_0_OR_GREATER
            return BitOperations.RotateRight(i, distance);
#else
            return (i >> distance) | (i << -distance);
#endif
        }
    }
}
