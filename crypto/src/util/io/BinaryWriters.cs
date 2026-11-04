using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    /// <summary>
    /// Utility methods for writing fixed-size values to a <see cref="BinaryWriter"/> in a given byte order.
    /// </summary>
    public static class BinaryWriters
    {
        /// <summary>Write a value to a writer in big-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteInt16BigEndian(BinaryWriter binaryWriter, short n)
        {
            short bigEndian = BitConverter.IsLittleEndian ? Shorts.ReverseBytes(n) : n;
            binaryWriter.Write(bigEndian);
        }

        /// <summary>Write a value to a writer in little-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteInt16LittleEndian(BinaryWriter binaryWriter, short n)
        {
            short littleEndian = BitConverter.IsLittleEndian ? n : Shorts.ReverseBytes(n);
            binaryWriter.Write(littleEndian);
        }

        /// <summary>Write a value to a writer in big-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteInt32BigEndian(BinaryWriter binaryWriter, int n)
        {
            int bigEndian = BitConverter.IsLittleEndian ? Integers.ReverseBytes(n) : n;
            binaryWriter.Write(bigEndian);
        }

        /// <summary>Write a value to a writer in little-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteInt32LittleEndian(BinaryWriter binaryWriter, int n)
        {
            int littleEndian = BitConverter.IsLittleEndian ? n : Integers.ReverseBytes(n);
            binaryWriter.Write(littleEndian);
        }

        /// <summary>Write a value to a writer in big-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteInt64BigEndian(BinaryWriter binaryWriter, long n)
        {
            long bigEndian = BitConverter.IsLittleEndian ? Longs.ReverseBytes(n) : n;
            binaryWriter.Write(bigEndian);
        }

        /// <summary>Write a value to a writer in little-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteInt64LittleEndian(BinaryWriter binaryWriter, long n)
        {
            long littleEndian = BitConverter.IsLittleEndian ? n : Longs.ReverseBytes(n);
            binaryWriter.Write(littleEndian);
        }

        /// <summary>Write a value to a writer in big-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        [CLSCompliant(false)]
        public static void WriteUInt16BigEndian(BinaryWriter binaryWriter, ushort n)
        {
            ushort bigEndian = BitConverter.IsLittleEndian ? Shorts.ReverseBytes(n) : n;
            binaryWriter.Write(bigEndian);
        }

        /// <summary>Write a value to a writer in little-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        [CLSCompliant(false)]
        public static void WriteUInt16LittleEndian(BinaryWriter binaryWriter, ushort n)
        {
            ushort littleEndian = BitConverter.IsLittleEndian ? n : Shorts.ReverseBytes(n);
            binaryWriter.Write(littleEndian);
        }

        /// <summary>Write a value to a writer in big-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        [CLSCompliant(false)]
        public static void WriteUInt32BigEndian(BinaryWriter binaryWriter, uint n)
        {
            uint bigEndian = BitConverter.IsLittleEndian ? Integers.ReverseBytes(n) : n;
            binaryWriter.Write(bigEndian);
        }

        /// <summary>Write a value to a writer in little-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        [CLSCompliant(false)]
        public static void WriteUInt32LittleEndian(BinaryWriter binaryWriter, uint n)
        {
            uint littleEndian = BitConverter.IsLittleEndian ? n : Integers.ReverseBytes(n);
            binaryWriter.Write(littleEndian);
        }

        /// <summary>Write a value to a writer in big-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        [CLSCompliant(false)]
        public static void WriteUInt64BigEndian(BinaryWriter binaryWriter, ulong n)
        {
            ulong bigEndian = BitConverter.IsLittleEndian ? Longs.ReverseBytes(n) : n;
            binaryWriter.Write(bigEndian);
        }

        /// <summary>Write a value to a writer in little-endian byte order.</summary>
        /// <param name="binaryWriter">The writer.</param>
        /// <param name="n">The value to write.</param>
        [CLSCompliant(false)]
        public static void WriteUInt64LittleEndian(BinaryWriter binaryWriter, ulong n)
        {
            ulong littleEndian = BitConverter.IsLittleEndian ? n : Longs.ReverseBytes(n);
            binaryWriter.Write(littleEndian);
        }
    }
}
