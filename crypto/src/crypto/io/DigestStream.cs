using System;
using System.IO;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    /// <summary>A stream that feeds the data read or written through it into a digest.</summary>
    public sealed class DigestStream
        : Stream
    {
        private readonly Stream m_stream;
        private readonly IDigest m_readDigest;
        private readonly IDigest m_writeDigest;

        /// <summary>Create a new <see cref="DigestStream"/>.</summary>
        /// <param name="stream">The stream.</param>
        /// <param name="readDigest">The read digest.</param>
        /// <param name="writeDigest">The write digest.</param>
        public DigestStream(Stream stream, IDigest readDigest, IDigest writeDigest)
        {
            m_stream = stream;
            m_readDigest = readDigest;
            m_writeDigest = writeDigest;
        }

        /// <summary>Gets the underlying stream.</summary>
        public Stream Stream => m_stream;

        /// <summary>Gets the read digest.</summary>
        public IDigest ReadDigest => m_readDigest;

        /// <summary>Gets the write digest.</summary>
        public IDigest WriteDigest => m_writeDigest;

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

            if (m_readDigest != null && n > 0)
            {
                m_readDigest.BlockUpdate(buffer, offset, n);
            }

            return n;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            int n = m_stream.Read(buffer);

            if (m_readDigest != null && n > 0)
            {
                m_readDigest.BlockUpdate(buffer[..n]);
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

            if (m_readDigest != null && b >= 0)
            {
                m_readDigest.Update((byte)b);
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
            if (m_writeDigest != null)
            {
                Streams.ValidateBufferArguments(buffer, offset, count);

                if (count > 0)
                {
                    m_writeDigest.BlockUpdate(buffer, offset, count);
                }
            }

            m_stream.Write(buffer, offset, count);
        }

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        /// <inheritdoc/>
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (m_writeDigest != null)
            {
                Streams.ValidateBufferArguments(buffer, offset, count);

                if (count > 0)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return Task.FromCanceled(cancellationToken);

                    m_writeDigest.BlockUpdate(buffer, offset, count);
                }
            }

            return m_stream.WriteAsync(buffer, offset, count, cancellationToken);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (m_writeDigest != null)
            {
                if (!buffer.IsEmpty)
                {
                    m_writeDigest.BlockUpdate(buffer);
                }
            }

            m_stream.Write(buffer);
        }

        /// <inheritdoc/>
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (m_writeDigest != null)
            {
                if (!buffer.IsEmpty)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return Streams.CanceledValueTask(cancellationToken);

                    m_writeDigest.BlockUpdate(buffer.Span);
                }
            }

            return m_stream.WriteAsync(buffer, cancellationToken);
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            if (m_writeDigest != null)
            {
                m_writeDigest.Update(value);
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

        private Stream ReadSource => m_readDigest == null ? m_stream : this;
    }
}
