using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public sealed class SignerStream
        : Stream
    {
        private readonly Stream m_stream;
        private readonly ISigner m_readSigner;
        private readonly ISigner m_writeSigner;

        public SignerStream(Stream stream, ISigner readSigner, ISigner writeSigner)
        {
            m_stream = stream;
            m_readSigner = readSigner;
            m_writeSigner = writeSigner;
        }

        public ISigner ReadSigner => m_readSigner;

        public ISigner WriteSigner => m_writeSigner;

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
            if (m_readSigner == null)
            {
                m_stream.CopyTo(destination, bufferSize);
            }
            else
            {
                base.CopyTo(destination, bufferSize);
            }
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

            if (m_readSigner != null && n > 0)
            {
                m_readSigner.BlockUpdate(buffer, offset, n);
            }

            return n;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int n = m_stream.Read(buffer);

            if (m_readSigner != null && n > 0)
            {
                m_readSigner.BlockUpdate(buffer[..n]);
            }

            return n;
        }
#endif

        public override int ReadByte()
        {
            int b = m_stream.ReadByte();

            if (m_readSigner != null && b >= 0)
            {
                m_readSigner.Update((byte)b);
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

            if (m_writeSigner != null && count > 0)
            {
                m_writeSigner.BlockUpdate(buffer, offset, count);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            m_stream.Write(buffer);

            if (m_writeSigner != null && !buffer.IsEmpty)
            {
                m_writeSigner.BlockUpdate(buffer);
            }
        }
#endif

        public override void WriteByte(byte value)
        {
            m_stream.WriteByte(value);

            if (m_writeSigner != null)
            {
                m_writeSigner.Update(value);
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
    }
}
