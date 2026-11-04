using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>An input stream that reads from a byte queue.</summary>
    public sealed class ByteQueueInputStream
        : BaseInputStream
    {
        private readonly ByteQueue m_buffer;

        /// <summary>Create a new <see cref="ByteQueueInputStream"/>.</summary>
        public ByteQueueInputStream()
        {
            this.m_buffer = new ByteQueue();
        }

        /// <summary>Add data to the end of the stream.</summary>
        /// <param name="buf">The data.</param>
        public void AddBytes(byte[] buf)
        {
            m_buffer.AddData(buf, 0, buf.Length);
        }

        /// <summary>Add data to the end of the stream.</summary>
        /// <param name="buf">The data.</param>
        /// <param name="bufOff">The offset into <paramref name="buf"/> at which the data starts.</param>
        /// <param name="bufLen">The number of bytes to add.</param>
        public void AddBytes(byte[] buf, int bufOff, int bufLen)
        {
            m_buffer.AddData(buf, bufOff, bufLen);
        }

        /// <summary>Copy data from the start of the stream without consuming it.</summary>
        /// <param name="buf">The buffer to copy to.</param>
        /// <returns>The number of bytes copied.</returns>
        public int Peek(byte[] buf)
        {
            int bytesToRead = System.Math.Min(m_buffer.Available, buf.Length);
            m_buffer.Read(buf, 0, bytesToRead, 0);
            return bytesToRead;
        }

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            int bytesToRead = System.Math.Min(m_buffer.Available, count);
            m_buffer.RemoveData(buffer, offset, bytesToRead, 0);
            return bytesToRead;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            int bytesToRead = System.Math.Min(m_buffer.Available, buffer.Length);
            m_buffer.RemoveData(buffer[..bytesToRead], 0);
            return bytesToRead;
        }
#endif

        /// <inheritdoc/>
        public override int ReadByte()
        {
            if (m_buffer.Available == 0)
                return -1;

            return m_buffer.RemoveData(1, 0)[0];
        }

        /// <summary>Skip over data in the stream.</summary>
        /// <param name="n">The number of bytes to skip.</param>
        /// <returns>The number of bytes actually skipped.</returns>
        public long Skip(long n)
        {
            int bytesToRemove = System.Math.Min((int)n, m_buffer.Available);
            m_buffer.RemoveData(bytesToRemove);
            return bytesToRemove;
        }

        /// <summary>Gets the available.</summary>
        public int Available
        {
            get { return m_buffer.Available; }
        }
    }
}
