using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities.IO
{
    public abstract class BaseInputStream
        : Stream
    {
        public sealed override bool CanRead { get { return true; } }
        public sealed override bool CanSeek { get { return false; } }
        public sealed override bool CanWrite { get { return false; } }

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Streams.CopyTo(this, destination, bufferSize);
        }
#endif

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return Streams.CopyToAsync(this, destination, bufferSize, cancellationToken);
        }

        public sealed override void Flush() {}
        public sealed override long Length { get { throw new NotSupportedException(); } }
        public sealed override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            int pos = 0;
            try
            {
                while (pos < count)
                {
                    int b = ReadByte();
                    if (b < 0)
                        break;

                    buffer[offset + pos++] = (byte)b;
                }
            }
            catch (IOException)
            {
                if (pos == 0)
                    throw;
            }
            return pos;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int count = buffer.Length, pos = 0;
            try
            {
                while (pos < count)
                {
                    int b = ReadByte();
                    if (b < 0)
                        break;

                    buffer[pos++] = (byte)b;
                }
            }
            catch (IOException)
            {
                if (pos == 0)
                    throw;
            }
            return pos;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(this, buffer, cancellationToken);
        }
#endif

        public sealed override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public sealed override void SetLength(long value) { throw new NotSupportedException(); }
        public sealed override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api] sealed
        public override void Write(ReadOnlySpan<byte> buffer) { throw new NotSupportedException(); }
        // TODO[api] sealed
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
#endif
    }
}
