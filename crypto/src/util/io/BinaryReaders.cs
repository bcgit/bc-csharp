using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    public static class BinaryReaders
    {
        internal static T Parse<T>(Func<BinaryReader, T> parse, Stream stream, bool leaveOpen)
        {
            using (var binaryReader = new BinaryReader(stream, Strings.UTF8, leaveOpen))
            {
                return parse(binaryReader);
            }
        }

        internal static T Parse<T>(Func<BinaryReader, T> parse, byte[] buf, int off, int len, string description)
        {
            using (var stream = new MemoryStream(buf, off, len, false))
            {
                T t = Parse(parse, stream, leaveOpen: true);
                if (stream.Position != stream.Length)
                    throw new IOException($"unexpected data found after {description}");
                return t;
            }
        }

        /// <summary>
        /// Read exactly <paramref name="count"/> bytes, or throw <see cref="EndOfStreamException"/>.
        /// </summary>
        /// <remarks>
        /// <paramref name="count"/> is typically a length field read from untrusted data, and
        /// <see cref="BinaryReader.ReadBytes(int)"/> allocates the whole result before reading anything, so a
        /// hostile length would otherwise cost up to 2GB of allocation before the data ran out. A count beyond
        /// the total length of a seekable stream is rejected up front, and a large count is read incrementally
        /// so that allocation tracks the data actually supplied.
        /// </remarks>
        /// <exception cref="IOException">if <paramref name="count"/> is negative.</exception>
        /// <exception cref="EndOfStreamException">if the stream ends before <paramref name="count"/> bytes.</exception>
        public static byte[] ReadBytesFully(BinaryReader binaryReader, int count)
        {
            if (count < 0)
                throw new IOException($"negative length: {count}");

            // The reader makes no promise about read-ahead, so the stream position is not a reliable measure of
            // the data remaining; only the total length is a safe bound.
            if (Streams.TryGetLength(binaryReader.BaseStream, out long length) && count > length)
                throw new EndOfStreamException();

            if (count > ReadBytesChunkSize)
                return ReadBytesFullyChunked(binaryReader, count);

            byte[] bytes = binaryReader.ReadBytes(count);
            if (bytes == null || bytes.Length != count)
                throw new EndOfStreamException();
            return bytes;
        }

        private const int ReadBytesChunkSize = 0x10000;

        // TODO[io] Has a lot in common with Streams.TryReadExactIncremental
        private static byte[] ReadBytesFullyChunked(BinaryReader binaryReader, int count)
        {
            using (var buf = new MemoryStream())
            {
                byte[] chunk = new byte[ReadBytesChunkSize];
                int remaining = count;
                while (remaining > 0)
                {
                    int numRead = binaryReader.Read(chunk, 0, System.Math.Min(chunk.Length, remaining));
                    if (numRead <= 0)
                        throw new EndOfStreamException();

                    buf.Write(chunk, 0, numRead);
                    remaining -= numRead;
                }
                return buf.ToArray();
            }
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
