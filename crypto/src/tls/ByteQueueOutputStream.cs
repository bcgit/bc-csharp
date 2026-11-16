using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>OutputStream based on a ByteQueue implementation.</summary>
    public sealed class ByteQueueOutputStream
        : BaseOutputStream
    {
        private readonly ByteQueue m_buffer;

        /// <summary>Create a new <see cref="ByteQueueOutputStream"/>.</summary>
        public ByteQueueOutputStream()
        {
            this.m_buffer = new ByteQueue();
        }

        /// <summary>Gets the buffer.</summary>
        public ByteQueue Buffer
        {
            get { return m_buffer; }
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            m_buffer.AddData(buffer, offset, count);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            m_buffer.AddData(buffer);
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            m_buffer.AddData(new byte[]{ value }, 0, 1);
        }
    }
}
