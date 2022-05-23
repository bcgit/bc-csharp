using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.IO
{
    public class DigestStream
        : Stream
    {
        protected readonly Stream stream;
        protected readonly IDigest inDigest;
        protected readonly IDigest outDigest;

        public DigestStream(Stream stream, IDigest readDigest, IDigest writeDigest)
        {
            this.stream = stream;
            this.inDigest = readDigest;
            this.outDigest = writeDigest;
        }

        public virtual IDigest ReadDigest()
        {
            return inDigest;
        }

        public virtual IDigest WriteDigest()
        {
            return outDigest;
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

            if (inDigest != null && n > 0)
            {
                inDigest.BlockUpdate(buffer, offset, n);
            }

            return n;
        }

        public override int ReadByte()
        {
            int b = stream.ReadByte();

            if (inDigest != null && b >= 0)
            {
                inDigest.Update((byte)b);
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

            if (outDigest != null && count > 0)
            {
                outDigest.BlockUpdate(buffer, offset, count);
            }
        }

        public override void WriteByte(byte value)
        {
            stream.WriteByte(value);

            if (outDigest != null)
            {
                outDigest.Update(value);
            }
        }
    }
}

