using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Utilities.IO
{
    public static class BinaryReaders
    {
        internal static T Parse<T>(Func<BinaryReader, T> parse, Stream stream, bool leaveOpen)
        {
            using (var binaryReader = new BinaryReader(stream, Encoding.UTF8, leaveOpen))
            {
                return parse(binaryReader);
            }
        }

        public static byte[] ReadBytesFully(BinaryReader binaryReader, int count)
        {
            byte[] bytes = binaryReader.ReadBytes(count);
            if (bytes == null || bytes.Length != count)
                throw new EndOfStreamException();
            return bytes;
        }

        public static short ReadInt16BigEndian(BinaryReader binaryReader)
        {
            short n = binaryReader.ReadInt16();
            return BitConverter.IsLittleEndian ? Shorts.ReverseBytes(n) : n;
        }

        public static short ReadInt16LittleEndian(BinaryReader binaryReader)
        {
            short n = binaryReader.ReadInt16();
            return BitConverter.IsLittleEndian ? n : Shorts.ReverseBytes(n);
        }

        public static int ReadInt32BigEndian(BinaryReader binaryReader)
        {
            int n = binaryReader.ReadInt32();
            return BitConverter.IsLittleEndian ? Integers.ReverseBytes(n) : n;
        }

        public static int ReadInt32LittleEndian(BinaryReader binaryReader)
        {
            int n = binaryReader.ReadInt32();
            return BitConverter.IsLittleEndian ? n : Integers.ReverseBytes(n);
        }

        public static long ReadInt64BigEndian(BinaryReader binaryReader)
        {
            long n = binaryReader.ReadInt64();
            return BitConverter.IsLittleEndian ? Longs.ReverseBytes(n) : n;
        }

        public static long ReadInt64LittleEndian(BinaryReader binaryReader)
        {
            long n = binaryReader.ReadInt64();
            return BitConverter.IsLittleEndian ? n : Longs.ReverseBytes(n);
        }

        [CLSCompliant(false)]
        public static ushort ReadUInt16BigEndian(BinaryReader binaryReader)
        {
            ushort n = binaryReader.ReadUInt16();
            return BitConverter.IsLittleEndian ? Shorts.ReverseBytes(n) : n;
        }

        [CLSCompliant(false)]
        public static ushort ReadUInt16LittleEndian(BinaryReader binaryReader)
        {
            ushort n = binaryReader.ReadUInt16();
            return BitConverter.IsLittleEndian ? n : Shorts.ReverseBytes(n);
        }

        [CLSCompliant(false)]
        public static uint ReadUInt32BigEndian(BinaryReader binaryReader)
        {
            uint n = binaryReader.ReadUInt32();
            return BitConverter.IsLittleEndian ? Integers.ReverseBytes(n) : n;
        }

        [CLSCompliant(false)]
        public static uint ReadUInt32LittleEndian(BinaryReader binaryReader)
        {
            uint n = binaryReader.ReadUInt32();
            return BitConverter.IsLittleEndian ? n : Integers.ReverseBytes(n);
        }

        [CLSCompliant(false)]
        public static ulong ReadUInt64BigEndian(BinaryReader binaryReader)
        {
            ulong n = binaryReader.ReadUInt64();
            return BitConverter.IsLittleEndian ? Longs.ReverseBytes(n) : n;
        }

        [CLSCompliant(false)]
        public static ulong ReadUInt64LittleEndian(BinaryReader binaryReader)
        {
            ulong n = binaryReader.ReadUInt64();
            return BitConverter.IsLittleEndian ? n : Longs.ReverseBytes(n);
        }
    }
}
