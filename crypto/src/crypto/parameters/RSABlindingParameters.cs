using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for RSA blinding: the public key and the blinding factor.</summary>
    public class RsaBlindingParameters
        : ICipherParameters
    {
        private readonly RsaKeyParameters publicKey;
        private readonly BigInteger blindingFactor;

        /// <summary>Create a new <see cref="RsaBlindingParameters"/>.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="blindingFactor">The blinding factor.</param>
        public RsaBlindingParameters(
            RsaKeyParameters publicKey,
            BigInteger blindingFactor)
        {
            if (publicKey.IsPrivate)
                throw new ArgumentException("RSA parameters should be for a public key");

            this.publicKey = publicKey;
            this.blindingFactor = blindingFactor;
        }

        /// <summary>Gets the public key.</summary>
        public RsaKeyParameters PublicKey
        {
            get { return publicKey; }
        }

        /// <summary>Gets the blinding factor.</summary>
        public BigInteger BlindingFactor
        {
            get { return blindingFactor; }
        }
    }
}
