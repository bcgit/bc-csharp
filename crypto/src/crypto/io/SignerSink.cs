using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public class SignerSink
		: BaseOutputStream
	{
		private readonly ISigner mSigner;

        public SignerSink(ISigner signer)
		{
            this.mSigner = signer;
		}

        public virtual ISigner Signer
        {
            get { return mSigner; }
        }

		public override void Write(byte[] buffer, int offset, int count)
		{
			Streams.ValidateBufferArguments(buffer, offset, count);

			if (count > 0)
			{
				mSigner.BlockUpdate(buffer, offset, count);
			}
		}

		public override void WriteByte(byte value)
		{
			mSigner.Update(value);
		}
	}
}
