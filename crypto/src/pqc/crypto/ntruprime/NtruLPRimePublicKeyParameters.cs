using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>An NTRU LPRime public key.</summary>
    public sealed class NtruLPRimePublicKeyParameters
        : NtruLPRimeKeyParameters
    {
        internal byte[] pubKey;

        /// <summary>Create a new <see cref="NtruLPRimePublicKeyParameters"/>.</summary>
        /// <param name="primeParameters">The prime parameters.</param>
        /// <param name="pubKey">The public key.</param>
        public NtruLPRimePublicKeyParameters(NtruLPRimeParameters primeParameters, byte[] pubKey)
            : base(false, primeParameters)
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
