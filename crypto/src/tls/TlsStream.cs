using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    internal class TlsStream
        : Stream
    {
        private readonly TlsProtocol m_handler;

        internal TlsStream(TlsProtocol handler)
        {
            m_handler = handler;
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

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

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_handler.Close();
            }
            base.Dispose(disposing);
        }

        public override void Flush()
        {
            m_handler.Flush();
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
            return m_handler.ReadApplicationData(buffer, offset, count);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            return m_handler.ReadApplicationData(buffer);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.ReadAsync(this, buffer, cancellationToken);
        }
#endif

        public override int ReadByte()
        {
            byte[] buf = new byte[1];
            int ret = m_handler.ReadApplicationData(buf, 0, 1);
            return ret <= 0 ? -1 : buf[0];
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            m_handler.WriteApplicationData(buffer, offset, count);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            m_handler.WriteApplicationData(buffer);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsync(this, buffer, cancellationToken);
        }
#endif

        public override void WriteByte(byte value)
        {
            m_handler.WriteApplicationData(new byte[]{ value }, 0, 1);
        }
    }
}
