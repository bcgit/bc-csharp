using System;
using System.IO;
using System.Threading;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class PipedStream
        : Stream
    {
        private readonly MemoryStream m_buf = new MemoryStream();
        private bool m_closed = false;

        private PipedStream m_other = null;
        private long m_readPos = 0;

        internal PipedStream()
        {
        }

        internal PipedStream(PipedStream other)
        {
            lock (other)
            {
                this.m_other = other;
                other.m_other = this;
            }
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

        public override void Flush()
        {
        }

        public override long Length
        {
            get { throw new NotImplementedException(); }
        }

        public override long Position
        {
            get { throw new NotImplementedException(); }
            set { throw new NotImplementedException(); }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            lock (m_other)
            {
                WaitForData();
                int len = System.Math.Min(count, Convert.ToInt32(m_other.m_buf.Position - m_readPos));
                Array.Copy(m_other.m_buf.GetBuffer(), m_readPos, buffer, offset, len);
                m_readPos += len;
                return len;
            }
        }

        public override int ReadByte()
        {
            lock (m_other)
            {
                WaitForData();
                bool eof = m_readPos >= m_other.m_buf.Position;
                return eof ? -1 : m_other.m_buf.GetBuffer()[m_readPos++];
            }
        }

        public override void Write(byte[] buf, int off, int len)
        {
            lock (this)
            {
                CheckOpen();
                m_buf.Write(buf, off, len);
                Monitor.PulseAll(this);
            }
        }

        public override void WriteByte(byte value)
        {
            lock (this)
            {
                CheckOpen();
                m_buf.WriteByte(value);
                Monitor.PulseAll(m_buf);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                lock (this)
                {
                    if (!m_closed)
                    {
                        m_closed = true;
                        Monitor.PulseAll(this);
                    }
                }
            }
        }

        private void CheckOpen()
        {
            if (m_closed)
                throw new ObjectDisposedException(this.GetType().Name);
        }

        private void WaitForData()
        {
            while (m_readPos >= m_other.m_buf.Position && !m_other.m_closed)
            {
                Monitor.Wait(m_other);
            }
        }
    }
}
