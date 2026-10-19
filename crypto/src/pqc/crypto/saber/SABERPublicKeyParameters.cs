using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberPublicKeyParameters
        : SaberKeyParameters
    {
        public readonly byte[] publicKey;

        /// <summary>Create a new <see cref="SaberPublicKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="publicKey">The public key.</param>
        public SaberPublicKeyParameters(SaberParameters parameters, byte[] publicKey)
            : base(false, parameters)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(publicKey);
        }

        /// <summary>Return the public key.</summary>
        public byte[] GetPublicKey()
        {
            return Arrays.Clone(publicKey);
        }
    }
}
