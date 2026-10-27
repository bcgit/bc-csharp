using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for AEAD cipher modes: a key, the MAC size, a nonce and optional associated data.</summary>
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

        /// <summary>Gets the key.</summary>
        public virtual KeyParameter Key
        {
            get { return key; }
        }

        /// <summary>Gets the mac size.</summary>
        public virtual int MacSize
        {
            get { return macSize; }
        }

        /// <summary>Return the associated text.</summary>
        public virtual byte[] GetAssociatedText()
        {
            return associatedText;
        }

        /// <summary>Return the nonce.</summary>
        public virtual byte[] GetNonce()
        {
            return (byte[])nonce.Clone();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> Nonce => nonce;
#endif
    }
}
