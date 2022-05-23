using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>OutputStream based on a ByteQueue implementation.</summary>
    public sealed class ByteQueueOutputStream
        : BaseOutputStream
    {
        private readonly ByteQueue m_buffer;

        public ByteQueueOutputStream()
        {
            this.m_buffer = new ByteQueue();
        }

        public ByteQueue Buffer
        {
            get { return m_buffer; }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            m_buffer.AddData(buffer, offset, count);
        }

        public override void WriteByte(byte value)
        {
            m_buffer.AddData(new byte[]{ value }, 0, 1);
        }
    }
}
