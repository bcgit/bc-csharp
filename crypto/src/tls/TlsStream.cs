using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    internal class TlsStream
        : Stream
    {
        private readonly TlsProtocol m_handler;

        internal TlsStream(TlsProtocol handler)
        {
            this.m_handler = handler;
        }

        public override bool CanRead
        {
            get { return !m_handler.IsClosed; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return !m_handler.IsClosed; }
        }

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_handler.Close();
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
        {
            m_handler.Close();
            base.Close();
        }
#endif

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

        public override int Read(byte[] buf, int off, int len)
        {
            return m_handler.ReadApplicationData(buf, off, len);
        }

        public override int ReadByte()
        {
            byte[] buf = new byte[1];
            int ret = Read(buf, 0, 1);
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

        public override void Write(byte[] buf, int off, int len)
        {
            m_handler.WriteApplicationData(buf, off, len);
        }

        public override void WriteByte(byte b)
        {
            Write(new byte[]{ b }, 0, 1);
        }
    }
}
