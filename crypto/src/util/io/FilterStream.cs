using System;
using System.IO;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

namespace Org.BouncyCastle.Utilities.IO
{
    /// <summary>
    /// A stream that forwards all operations to an underlying stream; subclasses override the operations they change.
    /// </summary>
    public class FilterStream
        : Stream
    {
        /// <summary>The underlying stream.</summary>
        protected readonly Stream s;

        /// <summary>Create a new <see cref="FilterStream"/>.</summary>
        /// <param name="s">The s.</param>
        public FilterStream(Stream s)
        {
            this.s = s ?? throw new ArgumentNullException(nameof(s));
        }
        /// <inheritdoc/>
        public override bool CanRead
        {
            get { return s.CanRead; }
        }
        /// <inheritdoc/>
        public override bool CanSeek
        {
            get { return s.CanSeek; }
        }
        /// <inheritdoc/>
        public override bool CanWrite
        {
            get { return s.CanWrite; }
        }
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Streams.CopyTo(s, destination, bufferSize);
        }
#endif
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        /// <inheritdoc/>
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return Streams.CopyToAsync(s, destination, bufferSize, cancellationToken);
        }
#endif
        /// <inheritdoc/>
        public override void Flush()
        {
            s.Flush();
        }
        /// <inheritdoc/>
        public override long Length
        {
            get { return s.Length; }
        }
        /// <inheritdoc/>
        public override long Position
        {
            get { return s.Position; }
            set { s.Position = value; }
        }
        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            return s.Read(buffer, offset, count);
        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            return s.Read(buffer);
        }
        /// <inheritdoc/>
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(s, buffer, cancellationToken);
        }
#endif
        /// <inheritdoc/>
        public override int ReadByte()
        {
            return s.ReadByte();
        }
        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin)
        {
            return s.Seek(offset, origin);
        }
        /// <inheritdoc/>
        public override void SetLength(long value)
        {
            s.SetLength(value);
        }
        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            s.Write(buffer, offset, count);
        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            s.Write(buffer);
        }
        /// <inheritdoc/>
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsync(s, buffer, cancellationToken);
        }
#endif
        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            s.WriteByte(value);
        }
        /// <summary>Dispose of this stream without disposing of the underlying stream.</summary>
        /// <param name="disposing">true when called from <c>Dispose</c>, false when called from a finalizer.</param>
        protected void Detach(bool disposing)
        {
            base.Dispose(disposing);
        }
        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                s.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
