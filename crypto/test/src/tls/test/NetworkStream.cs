using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class NetworkStream
        : Stream
    {
        private readonly Stream m_inner;
        private bool m_closed = false;

        internal NetworkStream(Stream inner)
        {
            this.m_inner = inner;
        }

        internal virtual bool IsClosed
        {
            get { lock (this) return m_closed; }
        }

        public override bool CanRead
        {
            get { return m_inner.CanRead; }
        }

        public override bool CanSeek
        {
            get { return m_inner.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return m_inner.CanWrite; }
        }

        public override void Flush()
        {
            m_inner.Flush();
        }

        public override long Length
        {
            get { return m_inner.Length; }
        }

        public override long Position
        {
            get { return m_inner.Position; }
            set { m_inner.Position = value; }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return m_inner.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            m_inner.SetLength(value);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            CheckNotClosed();
            return m_inner.Read(buffer, offset, count);
        }

        public override int ReadByte()
        {
            CheckNotClosed();
            return m_inner.ReadByte();
        }

        public override void Write(byte[] buf, int off, int len)
        {
            CheckNotClosed();
            m_inner.Write(buf, off, len);
        }

        public override void WriteByte(byte value)
        {
            CheckNotClosed();
            m_inner.WriteByte(value);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                lock (this) m_closed = true;
            }
        }

        private void CheckNotClosed()
        {
            lock (this)
            {
                if (m_closed)
                    throw new ObjectDisposedException(this.GetType().Name);
            }
        }
    }
}
