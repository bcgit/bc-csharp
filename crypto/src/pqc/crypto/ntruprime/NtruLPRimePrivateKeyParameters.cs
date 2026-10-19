using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>An NTRU LPRime private key.</summary>
    public sealed class NtruLPRimePrivateKeyParameters
        : NtruLPRimeKeyParameters
    {
        internal byte[] privKey;

        /// <summary>Create a new <see cref="NtruLPRimePrivateKeyParameters"/>.</summary>
        /// <param name="primeParameters">The prime parameters.</param>
        /// <param name="privKey">The private key.</param>
        public NtruLPRimePrivateKeyParameters(NtruLPRimeParameters primeParameters, byte[] privKey)
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
