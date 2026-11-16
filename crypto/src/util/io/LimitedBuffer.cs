using System;

namespace Org.BouncyCastle.Utilities.IO
{
    /// <summary>A write-only buffer that holds at most a fixed number of bytes.</summary>
    public sealed class LimitedBuffer
        : BaseOutputStream
    {
        private readonly byte[] m_buf;
        private int m_count;

        /// <summary>Create a new <see cref="LimitedBuffer"/>.</summary>
        /// <param name="limit">The limit.</param>
        public LimitedBuffer(int limit)
        {
            m_buf = new byte[limit];
            m_count = 0;
        }

        /// <summary>Copy the buffered bytes to a destination.</summary>
        /// <param name="buffer">The destination.</param>
        /// <param name="offset">The offset into <paramref name="buffer"/> at which to start writing.</param>
        /// <returns>The number of bytes copied.</returns>
        public int CopyTo(byte[] buffer, int offset)
        {
            Array.Copy(m_buf, 0, buffer, offset, m_count);
            return m_count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Copy the buffered bytes to a destination.</summary>
        /// <param name="buffer">The destination.</param>
        /// <returns>The number of bytes copied.</returns>
        public int CopyTo(Span<byte> buffer)
        {
            m_buf.AsSpan(0, m_count).CopyTo(buffer);
            return m_count;
        }
#endif

        /// <summary>Gets the count.</summary>
        public int Count => m_count;

        /// <summary>Gets the limit.</summary>
        public int Limit => m_buf.Length;

        /// <summary>Discard the buffered bytes.</summary>
        public void Reset()
        {
            m_count = 0;
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            Array.Copy(buffer, offset, m_buf, m_count, count);
            m_count += count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            buffer.CopyTo(m_buf.AsSpan(m_count));
            m_count += buffer.Length;
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            m_buf[m_count++] = value;
        }
    }
}
