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

        public static short ReverseBytes(short i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i, 8);
#endif
        }

        [CLSCompliant(false)]
        public static ushort ReverseBytes(ushort i)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReverseEndianness(i);
#else
            return RotateLeft(i, 8);
#endif
        }

        public static short RotateLeft(short i, int distance)
        {
            return (short)RotateLeft((ushort)i, distance);
        }

        [CLSCompliant(false)]
        public static ushort RotateLeft(ushort i, int distance)
        {
            return (ushort)((i << distance) | (i >> (16 - distance)));
        }

        public static short RotateRight(short i, int distance)
        {
            return (short)RotateRight((ushort)i, distance);
        }

        [CLSCompliant(false)]
        public static ushort RotateRight(ushort i, int distance)
        {
            return (ushort)((i >> distance) | (i << (16 - distance)));
        }
    }
}
