using System;
using System.IO;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public sealed class MacStream
        : Stream
    {
        private readonly Stream m_stream;
        private readonly IMac m_readMac;
        private readonly IMac m_writeMac;

        public MacStream(Stream stream, IMac readMac, IMac writeMac)
        {
            m_stream = stream;
            m_readMac = readMac;
            m_writeMac = writeMac;
        }

        public IMac ReadMac => m_readMac;

        public IMac WriteMac => m_writeMac;

        public override bool CanRead => m_stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => m_stream.CanWrite;

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Streams.CopyTo(ReadSource, destination, bufferSize);
        }
#endif

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return Streams.CopyToAsync(ReadSource, destination, bufferSize, cancellationToken);
        }
#endif

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
            int n = m_stream.Read(buffer, offset, count);

            if (m_readMac != null && n > 0)
            {
                m_readMac.BlockUpdate(buffer, offset, n);
            }

            return n;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int n = m_stream.Read(buffer);

            if (m_readMac != null && n > 0)
            {
                m_readMac.BlockUpdate(buffer[..n]);
            }

            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(ReadSource, buffer, cancellationToken);
        }
#endif

        public override int ReadByte()
        {
            int b = m_stream.ReadByte();

            if (m_readMac != null && b >= 0)
            {
                m_readMac.Update((byte)b);
            }

            return b;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long length) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (m_writeMac != null)
            {
                Streams.ValidateBufferArguments(buffer, offset, count);

                if (count > 0)
                {
                    m_writeMac.BlockUpdate(buffer, offset, count);
                }
            }

            m_stream.Write(buffer, offset, count);
        }

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (m_writeMac != null)
            {
                Streams.ValidateBufferArguments(buffer, offset, count);

                if (count > 0)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return Task.FromCanceled(cancellationToken);

                    m_writeMac.BlockUpdate(buffer, offset, count);
                }
            }

            return m_stream.WriteAsync(buffer, offset, count, cancellationToken);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (m_writeMac != null)
            {
                if (!buffer.IsEmpty)
                {
                    m_writeMac.BlockUpdate(buffer);
                }
            }

            m_stream.Write(buffer);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (m_writeMac != null)
            {
                if (!buffer.IsEmpty)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return ValueTask.FromCanceled(cancellationToken);

                    m_writeMac.BlockUpdate(buffer.Span);
                }
            }

            return m_stream.WriteAsync(buffer, cancellationToken);
        }
#endif

        public override void WriteByte(byte value)
        {
            if (m_writeMac != null)
            {
                m_writeMac.Update(value);
            }

            m_stream.WriteByte(value);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_stream.Dispose();
            }
            base.Dispose(disposing);
        }

        private Stream ReadSource => m_readMac == null ? m_stream : this;
    }
}
