using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.IO
{
    public class SignerStream
        : Stream
    {
        protected readonly Stream stream;
        protected readonly ISigner inSigner;
        protected readonly ISigner outSigner;

        public SignerStream(Stream stream, ISigner readSigner, ISigner writeSigner)
        {
            this.stream = stream;
            this.inSigner = readSigner;
            this.outSigner = writeSigner;
        }

        public virtual ISigner ReadSigner()
        {
            return inSigner;
        }

        public virtual ISigner WriteSigner()
        {
            return outSigner;
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

            if (inSigner != null && n > 0)
            {
                inSigner.BlockUpdate(buffer, offset, n);
            }

            return n;
        }

        public override int ReadByte()
        {
            int b = stream.ReadByte();

            if (inSigner != null && b >= 0)
            {
                inSigner.Update((byte)b);
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

            if (outSigner != null && count > 0)
            {
                outSigner.BlockUpdate(buffer, offset, count);
            }
        }

        public override void WriteByte(byte value)
        {
            stream.WriteByte(value);

            if (outSigner != null)
            {
                outSigner.Update(value);
            }
        }
    }
}

