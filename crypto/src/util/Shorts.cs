using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
#endif

namespace Org.BouncyCastle.Utilities
{
    /// <summary>Utility methods and constants for working with 16-bit integers.</summary>
    public static class Shorts
    {
        /// <summary>The <c>NumBits</c> constant, with the value <c>16</c>.</summary>
        public const int NumBits = 16;
        /// <summary>The <c>NumBytes</c> constant, with the value <c>2</c>.</summary>
        public const int NumBytes = 2;

        /// <summary>Reverse the order of the bytes of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bytes in reverse order.</returns>
        public static short ReverseBytes(short i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i, 8);
#endif
        }

        /// <summary>Reverse the order of the bytes of a value.</summary>
        /// <param name="i">The value.</param>
        /// <returns>The value with its bytes in reverse order.</returns>
        [CLSCompliant(false)]
        public static ushort ReverseBytes(ushort i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i, 8);
#endif
        }

        /// <summary>Rotate the bits of a value to the left.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        public static short RotateLeft(short i, int distance)
        {
            return (short)RotateLeft((ushort)i, distance);
        }

        /// <summary>Rotate the bits of a value to the left.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        [CLSCompliant(false)]
        public static ushort RotateLeft(ushort i, int distance)
        {
            return (ushort)((i << distance) | (i >> (16 - distance)));
        }

        /// <summary>Rotate the bits of a value to the right.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        public static short RotateRight(short i, int distance)
        {
            return (short)RotateRight((ushort)i, distance);
        }

        /// <summary>Rotate the bits of a value to the right.</summary>
        /// <param name="i">The value.</param>
        /// <param name="distance">The number of bit positions to rotate by.</param>
        /// <returns>The rotated value.</returns>
        [CLSCompliant(false)]
        public static ushort RotateRight(ushort i, int distance)
        {
            return (ushort)((i >> distance) | (i << (16 - distance)));
        }
    }
}
