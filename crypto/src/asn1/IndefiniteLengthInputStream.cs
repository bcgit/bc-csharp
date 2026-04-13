using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    internal class IndefiniteLengthInputStream
        : LimitedInputStream
    {
        private int m_lookAhead;
        private bool m_eofOn00 = true;

        internal IndefiniteLengthInputStream(Stream inStream, int limit)
            : base(inStream, limit)
        {
            m_lookAhead = RequireByte();

            if (0 == m_lookAhead)
            {
                CheckEndOfContents();
            }
        }

        internal void SetEofOn00(bool eofOn00)
        {
            m_eofOn00 = eofOn00;
            if (m_eofOn00 && 0 == m_lookAhead)
            {
                CheckEndOfContents();
            }
        }

        private void CheckEndOfContents()
        {
            if (0 != RequireByte())
                throw new IOException("malformed end-of-contents marker");

            m_lookAhead = -1;
            EnableParentEofDetect();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Only use this optimisation if we aren't checking for 00
            if (m_eofOn00 || count <= 1)
                return base.Read(buffer, offset, count);

            if (m_lookAhead < 0)
                return 0;

            int numRead = m_in.Read(buffer, offset + 1, count - 1);
            if (numRead <= 0)
                throw new EndOfStreamException();

            buffer[offset] = (byte)m_lookAhead;
            m_lookAhead = RequireByte();

            return numRead + 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            // Only use this optimisation if we aren't checking for 00
            if (m_eofOn00 || buffer.Length <= 1)
                return base.Read(buffer);

            if (m_lookAhead < 0)
                return 0;

            int numRead = m_in.Read(buffer[1..]);
            if (numRead <= 0)
                throw new EndOfStreamException();

            buffer[0] = (byte)m_lookAhead;
            m_lookAhead = RequireByte();

            return numRead + 1;
        }
#endif

        public override int ReadByte()
        {
            if (m_eofOn00 && m_lookAhead <= 0)
            {
                if (0 == m_lookAhead)
                {
                    CheckEndOfContents();
                }
                return -1;
            }

            int result = m_lookAhead;
            m_lookAhead = RequireByte();
            return result;
        }

        private int RequireByte()
        {
            int b = m_in.ReadByte();
            if (b < 0)
                throw new EndOfStreamException();

            return b;
        }
    }
}
