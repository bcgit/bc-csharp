using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>A Streamlined NTRU Prime private key.</summary>
    public sealed class SNtruPrimePrivateKeyParameters
        : SNtruPrimeKeyParameters
    {
        internal byte[] privKey;

        /// <summary>Create a new <see cref="SNtruPrimePrivateKeyParameters"/>.</summary>
        /// <param name="primeParameters">The prime parameters.</param>
        /// <param name="privKey">The private key.</param>
        public SNtruPrimePrivateKeyParameters(SNtruPrimeParameters primeParameters, byte[] privKey)
            : base(true, primeParameters)
        {
            this.privKey = Arrays.Clone(privKey);
        }

        /// <summary>Return the private key.</summary>
        public byte[] GetPrivateKey()
        {
            return Arrays.Clone(privKey);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return GetPrivateKey();
        }
    }
}
