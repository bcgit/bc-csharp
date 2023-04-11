using System;
using System.IO;
using System.Threading;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
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
            m_stream.Write(buffer, offset, count);

            if (m_writeMac != null && count > 0)
            {
                m_writeMac.BlockUpdate(buffer, offset, count);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            m_stream.Write(buffer);

            if (m_writeMac != null && !buffer.IsEmpty)
            {
                m_writeMac.BlockUpdate(buffer);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsync(WriteDestination, buffer, cancellationToken);
        }
#endif

        public override void WriteByte(byte value)
        {
            m_stream.WriteByte(value);

            if (m_writeMac != null)
            {
                m_writeMac.Update(value);
            }
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
        private Stream WriteDestination => m_writeMac == null ? m_stream : this;
    }
}
