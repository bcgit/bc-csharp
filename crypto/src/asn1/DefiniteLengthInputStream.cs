using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    internal class DefiniteLengthInputStream
        : LimitedInputStream
    {
        private static readonly byte[] EmptyBytes = Array.Empty<byte>();

        private readonly int m_originalLength;
        private int m_remaining;

        internal DefiniteLengthInputStream(Stream inStream, int length, int limit)
            : base(inStream, limit)
        {
            if (length <= 0)
            {
                if (length < 0)
                    throw new ArgumentException("negative lengths not allowed", "length");

                EnableParentEofDetect();
            }

            m_originalLength = length;
            m_remaining = length;
        }

        internal int Remaining => m_remaining;

        public override int ReadByte()
        {
            if (m_remaining < 2)
            {
                if (m_remaining == 0)
                    return -1;

                int b = m_in.ReadByte();
                if (b < 0)
                    throw new EndOfStreamException("DEF length " + m_originalLength + " object truncated by " + m_remaining);

                m_remaining = 0;
                EnableParentEofDetect();

                return b;
            }
            else
            {
                int b = m_in.ReadByte();
                if (b < 0)
                    throw new EndOfStreamException("DEF length " + m_originalLength + " object truncated by " + m_remaining);

                --m_remaining;
                return b;
            }
        }

        public override int Read(byte[] buf, int off, int len)
        {
            if (m_remaining == 0)
                return 0;

            int toRead = System.Math.Min(len, m_remaining);
            int numRead = m_in.Read(buf, off, toRead);

            if (numRead < 1)
                throw new EndOfStreamException("DEF length " + m_originalLength + " object truncated by " + m_remaining);

            if ((m_remaining -= numRead) == 0)
            {
                EnableParentEofDetect();
            }

            return numRead;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            if (m_remaining == 0)
                return 0;

            int toRead = System.Math.Min(buffer.Length, m_remaining);
            int numRead = m_in.Read(buffer[..toRead]);

            if (numRead < 1)
                throw new EndOfStreamException("DEF length " + m_originalLength + " object truncated by " + m_remaining);

            if ((m_remaining -= numRead) == 0)
            {
                EnableParentEofDetect();
            }

            return numRead;
        }
#endif

        internal void ReadAllIntoByteArray(byte[] buf)
        {
            if (m_remaining != buf.Length)
                throw new ArgumentException("buffer length not right for data");

            if (m_remaining == 0)
                return;

            // make sure it's safe to do this!
            int limit = Limit;
            if (m_remaining >= limit)
                throw new IOException("corrupted stream - out of bounds length found: " + m_remaining + " >= " + limit);

            if ((m_remaining -= Streams.ReadFully(m_in, buf, 0, buf.Length)) != 0)
                throw new EndOfStreamException("DEF length " + m_originalLength + " object truncated by " + m_remaining);
            EnableParentEofDetect();
        }

        internal byte[] ToArray()
        {
            if (m_remaining == 0)
                return EmptyBytes;

            // make sure it's safe to do this!
            int limit = Limit;
            if (m_remaining >= limit)
                throw new IOException("corrupted stream - out of bounds length found: " + m_remaining + " >= " + limit);

            byte[] bytes = new byte[m_remaining];
            if ((m_remaining -= Streams.ReadFully(m_in, bytes, 0, bytes.Length)) != 0)
                throw new EndOfStreamException("DEF length " + m_originalLength + " object truncated by " + m_remaining);
            EnableParentEofDetect();
            return bytes;
        }
    }
}
