using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public sealed class CipherStream
        : Stream
    {
        private readonly Stream m_stream;
        private readonly IBufferedCipher m_readCipher, m_writeCipher;

        private byte[] m_readBuf;
        private int m_readBufPos;
        private bool m_readEnded;

        public CipherStream(Stream stream, IBufferedCipher readCipher, IBufferedCipher writeCipher)
        {
            m_stream = stream;

            if (readCipher != null)
            {
                m_readCipher = readCipher;
                m_readBuf = null;
            }

            if (writeCipher != null)
            {
                m_writeCipher = writeCipher;
            }
        }

        public IBufferedCipher ReadCipher => m_readCipher;

        public IBufferedCipher WriteCipher => m_writeCipher;

        public override bool CanRead
        {
            get { return m_stream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return m_stream.CanWrite; }
        }

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Streams.CopyTo(ReadSource, destination, bufferSize);
        }
#endif

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return Streams.CopyToAsync(ReadSource, destination, bufferSize, cancellationToken);
        }

        public override void Flush()
        {
            m_stream.Flush();
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (m_readCipher == null)
                return m_stream.Read(buffer, offset, count);

            Streams.ValidateBufferArguments(buffer, offset, count);

            int num = 0;
            while (num < count)
            {
                if (m_readBuf == null || m_readBufPos >= m_readBuf.Length)
                {
                    if (!FillInBuf())
                        break;
                }

                int numToCopy = System.Math.Min(count - num, m_readBuf.Length - m_readBufPos);
                Array.Copy(m_readBuf, m_readBufPos, buffer, offset + num, numToCopy);
                m_readBufPos += numToCopy;
                num += numToCopy;
            }

            return num;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            if (buffer.IsEmpty)
                return 0;

            if (m_readCipher == null)
                return m_stream.Read(buffer);

            int num = 0;
            while (num < buffer.Length)
            {
                if (m_readBuf == null || m_readBufPos >= m_readBuf.Length)
                {
                    if (!FillInBuf())
                        break;
                }

                int numToCopy = System.Math.Min(buffer.Length - num, m_readBuf.Length - m_readBufPos);
                m_readBuf.AsSpan(m_readBufPos, numToCopy).CopyTo(buffer[num..]);

                m_readBufPos += numToCopy;
                num += numToCopy;
            }

            return num;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(ReadSource, buffer, cancellationToken);
        }
#endif

        public override int ReadByte()
        {
            if (m_readCipher == null)
                return m_stream.ReadByte();

            if (m_readBuf == null || m_readBufPos >= m_readBuf.Length)
            {
                if (!FillInBuf())
                    return -1;
            }

            return m_readBuf[m_readBufPos++];
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long length)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (m_writeCipher == null)
            {
                m_stream.Write(buffer, offset, count);
                return;
            }

            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count < 1)
                return;

            int outputSize = m_writeCipher.GetUpdateOutputSize(count);

            byte[] output = null;
            if (outputSize > 0)
            {
                output = new byte[outputSize];
            }

            try
            {
                int length = m_writeCipher.ProcessBytes(buffer, offset, count, output, 0);
                if (length > 0)
                {
                    m_stream.Write(output, 0, length);
                }
            }
            finally
            {
                if (output != null)
                {
                    Array.Clear(output, 0, output.Length);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (m_writeCipher == null)
            {
                m_stream.Write(buffer);
                return;
            }

            if (buffer.IsEmpty)
                return;

            int outputSize = m_writeCipher.GetUpdateOutputSize(buffer.Length);

            byte[] output = null;
            if (outputSize > 0)
            {
                output = new byte[outputSize];
            }

            try
            {
                int length = m_writeCipher.ProcessBytes(buffer, Spans.FromNullable(output));
                if (length > 0)
                {
                    m_stream.Write(output[..length]);
                }
            }
            finally
            {
                if (output != null)
                {
                    Array.Clear(output, 0, output.Length);
                }
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsync(WriteDestination, buffer, cancellationToken);
        }
#endif

        public override void WriteByte(byte value)
        {
            if (m_writeCipher == null)
            {
                m_stream.WriteByte(value);
                return;
            }

            byte[] data = m_writeCipher.ProcessByte(value);
            if (data != null)
            {
                m_stream.Write(data, 0, data.Length);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
			    if (m_writeCipher != null)
			    {
                    int outputSize = m_writeCipher.GetOutputSize(0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> output = outputSize <= 256
                        ? stackalloc byte[outputSize]
                        : new byte[outputSize];
                    int len = m_writeCipher.DoFinal(output);
                    m_stream.Write(output[..len]);
                    output.Fill(0x00);
#else
                    byte[] output = new byte[outputSize];
                    int len = m_writeCipher.DoFinal(output, 0);
                    m_stream.Write(output, 0, len);
                    Array.Clear(output, 0, output.Length);
#endif
                }
                m_stream.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool FillInBuf()
        {
            if (m_readEnded)
                return false;

            m_readBufPos = 0;

            do
            {
                m_readBuf = ReadAndProcessBlock();
            }
            while (!m_readEnded && m_readBuf == null);

            return m_readBuf != null;
        }

        private byte[] ReadAndProcessBlock()
        {
            int blockSize = m_readCipher.GetBlockSize();
            int readSize = blockSize == 0 ? 256 : blockSize;

            byte[] block = new byte[readSize];
            int numRead = 0;
            do
            {
                int count = m_stream.Read(block, numRead, block.Length - numRead);
                if (count < 1)
                {
                    m_readEnded = true;
                    break;
                }
                numRead += count;
            }
            while (numRead < block.Length);

            Debug.Assert(m_readEnded || numRead == block.Length);

            byte[] bytes = m_readEnded
                ? m_readCipher.DoFinal(block, 0, numRead)
                : m_readCipher.ProcessBytes(block);

            if (bytes != null && bytes.Length == 0)
            {
                bytes = null;
            }

            return bytes;
        }

        private Stream ReadSource => m_readCipher == null ? m_stream : this;
        private Stream WriteDestination => m_writeCipher == null ? m_stream : this;
    }
}
