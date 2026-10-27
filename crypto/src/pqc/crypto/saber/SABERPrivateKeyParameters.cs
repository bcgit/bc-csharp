using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    /// <summary>A SABER private key.</summary>
    public sealed class SaberPrivateKeyParameters
        : SaberKeyParameters
    {
        private readonly byte[] privateKey;

        /// <summary>Create a new <see cref="SaberPrivateKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="privateKey">The private key.</param>
        public SaberPrivateKeyParameters(SaberParameters parameters, byte[] privateKey)
            : base(true, parameters)
        {
            this.privateKey = Arrays.Clone(privateKey);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(privateKey);
        }

        /// <summary>Return the private key.</summary>
        public byte[] GetPrivateKey()
        {
            return Arrays.Clone(privateKey);
        }
    }
}
