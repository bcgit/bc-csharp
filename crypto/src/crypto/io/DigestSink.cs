using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public class DigestSink
        : BaseOutputStream
    {
        private readonly IDigest mDigest;

        public DigestSink(IDigest digest)
        {
            this.mDigest = digest;
        }

        public virtual IDigest Digest
        {
            get { return mDigest; }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count > 0)
            {
                mDigest.BlockUpdate(buffer, offset, count);
            }
        }

        public override void WriteByte(byte value)
        {
            mDigest.Update(value);
        }
    }
}
