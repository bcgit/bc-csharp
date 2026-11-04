using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for IES that also specify the size of the cipher key.</summary>
    public class IesWithCipherParameters : IesParameters
    {
        private int cipherKeySize;

        /**
         * @param derivation the derivation parameter for the KDF function.
         * @param encoding the encoding parameter for the KDF function.
         * @param macKeySize the size of the MAC key (in bits).
         * @param cipherKeySize the size of the associated Cipher key (in bits).
         */
        public IesWithCipherParameters(
            byte[]  derivation,
            byte[]  encoding,
            int     macKeySize,
            int     cipherKeySize) : base(derivation, encoding, macKeySize)
        {
            this.cipherKeySize = cipherKeySize;
        }

        /// <summary>Gets the cipher key size.</summary>
        public int CipherKeySize
        {
            get
            {
                return cipherKeySize;
            }
        }
    }

}
