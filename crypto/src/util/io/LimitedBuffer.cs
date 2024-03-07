using System;

namespace Org.BouncyCastle.Utilities.IO
{
    public sealed class LimitedBuffer
        : BaseOutputStream
    {
        private readonly byte[] m_buf;
        private int m_count;

        public LimitedBuffer(int limit)
        {
            m_buf = new byte[limit];
            m_count = 0;
        }

        public int CopyTo(byte[] buffer, int offset)
        {
            Array.Copy(m_buf, 0, buffer, offset, m_count);
            return m_count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int CopyTo(Span<byte> buffer)
        {
            m_buf.AsSpan(0, m_count).CopyTo(buffer);
            return m_count;
        }
#endif

        public int Count => m_count;

        public int Limit => m_buf.Length;

        public void Reset()
        {
            m_count = 0;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Array.Copy(buffer, offset, m_buf, m_count, count);
            m_count += count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            buffer.CopyTo(m_buf.AsSpan(m_count));
            m_count += buffer.Length;
        }
#endif

        public override void WriteByte(byte value)
        {
            m_buf[m_count++] = value;
        }
    }
}
