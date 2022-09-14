using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.IO
{
    public class MacStream
        : Stream
    {
        protected readonly Stream stream;
        protected readonly IMac inMac;
        protected readonly IMac outMac;

        public MacStream(Stream stream, IMac readMac, IMac writeMac)
        {
            this.stream = stream;
            this.inMac = readMac;
            this.outMac = writeMac;
        }

        public virtual IMac ReadMac()
        {
            return inMac;
        }

        public virtual IMac WriteMac()
        {
            return outMac;
        }

        public override bool CanRead
        {
            get { return stream.CanRead; }
        }

        public sealed override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return stream.CanWrite; }
        }

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Platform.Dispose(stream);
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
        {
            Platform.Dispose(stream);
            base.Close();
        }
#endif

        public override void Flush()
        {
            stream.Flush();
        }

        public sealed override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public sealed override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = stream.Read(buffer, offset, count);

            if (inMac != null && n > 0)
            {
                inMac.BlockUpdate(buffer, offset, n);
            }

            return n;
        }

        public override int ReadByte()
        {
            int b = stream.ReadByte();

            if (inMac != null && b >= 0)
            {
                inMac.Update((byte)b);
            }

            return b;
        }

        public sealed override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public sealed override void SetLength(long length)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            stream.Write(buffer, offset, count);

            if (outMac != null && count > 0)
            {
                outMac.BlockUpdate(buffer, offset, count);
            }
        }

        public override void WriteByte(byte value)
        {
            stream.WriteByte(value);

            if (outMac != null)
            {
                outMac.Update(value);
            }
        }
    }
}

