using System;
using System.IO;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

namespace Org.BouncyCastle.Utilities.IO
{
    public abstract class BaseOutputStream
        : Stream
    {
        public sealed override bool CanRead { get { return false; } }
        public sealed override bool CanSeek { get { return false; } }
        public sealed override bool CanWrite { get { return true; } }

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api] sealed
        public override void CopyTo(Stream destination, int bufferSize) { throw new NotSupportedException(); }
#endif

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        // TODO[api] sealed
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }
#endif

        public override void Flush() {}
        public sealed override long Length { get { throw new NotSupportedException(); } }
        public sealed override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }
        public sealed override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public sealed override int Read(Span<byte> buffer) { throw new NotSupportedException(); }
        // TODO[api] sealed
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
#endif
        // TODO[api] ReadByte
        public sealed override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public sealed override void SetLength(long value) { throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            for (int i = 0; i < count; ++i)
            {
                WriteByte(buffer[offset + i]);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            int count = buffer.Length;
            for (int i = 0; i < count; ++i)
            {
                WriteByte(buffer[i]);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsync(this, buffer, cancellationToken);
        }
#endif

        public virtual void Write(params byte[] buffer)
        {
            Write(buffer, 0, buffer.Length);
        }
    }
}
