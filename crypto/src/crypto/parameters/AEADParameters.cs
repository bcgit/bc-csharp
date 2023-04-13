using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class AeadParameters
		: ICipherParameters
	{
		private readonly byte[] associatedText;
		private readonly byte[] nonce;
		private readonly KeyParameter key;
		private readonly int macSize;

        /**
         * Base constructor.
         *
         * @param key key to be used by underlying cipher
         * @param macSize macSize in bits
         * @param nonce nonce to be used
         */
        public AeadParameters(KeyParameter key, int macSize, byte[] nonce)
           : this(key, macSize, nonce, null)
        {
        }

        /**
		 * Base constructor.
		 *
		 * @param key key to be used by underlying cipher
		 * @param macSize macSize in bits
		 * @param nonce nonce to be used
		 * @param associatedText associated text, if any
		 */
		public AeadParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText)
		{
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            this.key = key;
			this.nonce = nonce;
			this.macSize = macSize;
			this.associatedText = associatedText;
		}

		public virtual KeyParameter Key
		{
			get { return key; }
		}

		public virtual int MacSize
		{
			get { return macSize; }
		}

		public virtual byte[] GetAssociatedText()
		{
			return associatedText;
		}

		public virtual byte[] GetNonce()
		{
			return (byte[])nonce.Clone();
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> Nonce => nonce;
#endif
    }
}
