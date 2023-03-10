using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities.IO
{
    public class FilterStream
        : Stream
    {
        protected readonly Stream s;

        public FilterStream(Stream s)
        {
            this.s = s ?? throw new ArgumentNullException(nameof(s));
        }
        public override bool CanRead
        {
            get { return s.CanRead; }
        }
        public override bool CanSeek
        {
            get { return s.CanSeek; }
        }
        public override bool CanWrite
        {
            get { return s.CanWrite; }
        }
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Streams.CopyTo(s, destination, bufferSize);
        }
#endif
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return Streams.CopyToAsync(s, destination, bufferSize, cancellationToken);
        }
        public override void Flush()
        {
            s.Flush();
        }
        public override long Length
        {
            get { return s.Length; }
        }
        public override long Position
        {
            get { return s.Position; }
            set { s.Position = value; }
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            return s.Read(buffer, offset, count);
        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            return s.Read(buffer);
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(s, buffer, cancellationToken);
        }
#endif
        public override int ReadByte()
        {
            return s.ReadByte();
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            return s.Seek(offset, origin);
        }
        public override void SetLength(long value)
        {
            s.SetLength(value);
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            s.Write(buffer, offset, count);
        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            s.Write(buffer);
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsync(s, buffer, cancellationToken);
        }
#endif
        public override void WriteByte(byte value)
        {
            s.WriteByte(value);
        }
        protected void Detach(bool disposing)
        {
            base.Dispose(disposing);
        }
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
