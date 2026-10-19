using System;
using System.IO;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    /// <summary>A stream that feeds the data read or written through it into a MAC.</summary>
    public sealed class MacStream
        : Stream
    {
        private readonly Stream m_stream;
        private readonly IMac m_readMac;
        private readonly IMac m_writeMac;

        /// <summary>Create a new <see cref="MacStream"/>.</summary>
        /// <param name="stream">The stream.</param>
        /// <param name="readMac">The read mac.</param>
        /// <param name="writeMac">The write mac.</param>
        public MacStream(Stream stream, IMac readMac, IMac writeMac)
        {
            m_stream = stream;
            m_readMac = readMac;
            m_writeMac = writeMac;
        }

        public Stream Stream => m_stream;

        /// <summary>Gets the read mac.</summary>
        public IMac ReadMac => m_readMac;

        /// <summary>Gets the write mac.</summary>
        public IMac WriteMac => m_writeMac;

        /// <inheritdoc/>
        public override bool CanRead => m_stream.CanRead;

        /// <inheritdoc/>
        public override bool CanSeek => false;

        /// <inheritdoc/>
        public override bool CanWrite => m_stream.CanWrite;

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Streams.CopyTo(ReadSource, destination, bufferSize);
        }
#endif

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        /// <inheritdoc/>
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return Streams.CopyToAsync(ReadSource, destination, bufferSize, cancellationToken);
        }
#endif

        /// <inheritdoc/>
        public override void Flush()
        {
            m_stream.Flush();
        }

        /// <inheritdoc/>
        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        /// <inheritdoc/>
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        /// <inheritdoc/>
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
        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            int n = m_stream.Read(buffer);

            if (m_readMac != null && n > 0)
            {
                m_readMac.BlockUpdate(buffer[..n]);
            }

            return n;
        }

        /// <inheritdoc/>
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(ReadSource, buffer, cancellationToken);
        }
#endif

        /// <inheritdoc/>
        public override int ReadByte()
        {
            int b = m_stream.ReadByte();

            if (m_readMac != null && b >= 0)
            {
                m_readMac.Update((byte)b);
            }

            return b;
        }

        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void SetLength(long length) => throw new NotSupportedException();

        /// <inheritdoc/>
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
        /// <inheritdoc/>
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
        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (m_writeMac != null)
            {
                if (!buffer.IsEmpty)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return Streams.CanceledValueTask(cancellationToken);

                    m_writeMac.BlockUpdate(buffer.Span);
                }
            }

            return m_stream.WriteAsync(buffer, cancellationToken);
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            if (m_writeMac != null)
            {
                m_writeMac.Update(value);
            }

            m_stream.WriteByte(value);
        }

        /// <inheritdoc/>
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
