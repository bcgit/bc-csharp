using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public sealed class SNtruPrimePublicKeyParameters
        : SNtruPrimeKeyParameters
    {
        internal byte[] pubKey;

        /// <summary>Create a new <see cref="SNtruPrimePublicKeyParameters"/>.</summary>
        /// <param name="primeParameters">The prime parameters.</param>
        /// <param name="pubKey">The public key.</param>
        public SNtruPrimePublicKeyParameters(SNtruPrimeParameters primeParameters, byte[] pubKey) : base(false, primeParameters)
        {
            this.pubKey = Arrays.Clone(pubKey);
        }

        /// <summary>Return the public key.</summary>
        public byte[] GetPublicKey()
        {
            return Arrays.Clone(pubKey);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }
    }
}
