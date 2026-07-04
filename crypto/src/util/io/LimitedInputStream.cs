using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    internal sealed class LimitedInputStream
        : BaseInputStream
    {
        private readonly Stream m_stream;
        private readonly bool m_leaveOpen;
        private long m_currentLimit;

        internal LimitedInputStream(long limit, Stream stream, bool leaveOpen = false)
        {
            m_stream = stream;
            m_leaveOpen = leaveOpen;
            m_currentLimit = limit;
        }

        internal long CurrentLimit => m_currentLimit;

        public override int Read(byte[] buffer, int offset, int count)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Read(buffer.AsSpan(offset, count));
#else
            int numRead = m_stream.Read(buffer, offset, count);
            if (numRead > 0)
            {
                if ((m_currentLimit -= numRead) < 0)
                    throw new StreamOverflowException("Data Overflow");
            }
            return numRead;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int numRead = m_stream.Read(buffer);
            if (numRead > 0)
            {
                if ((m_currentLimit -= numRead) < 0)
                    throw new StreamOverflowException("Data Overflow");
            }
            return numRead;
        }
#endif

        public override int ReadByte()
        {
            int b = m_stream.ReadByte();
            if (b >= 0)
            {
                if (--m_currentLimit < 0)
                    throw new StreamOverflowException("Data Overflow");
            }
            return b;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (!m_leaveOpen)
                {
                    m_stream.Dispose();
                }
            }

            base.Dispose(disposing);
        }
    }
}
