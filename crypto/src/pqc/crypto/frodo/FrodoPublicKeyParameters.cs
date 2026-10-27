using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    /// <summary>A FrodoKEM public key.</summary>
    public sealed class FrodoPublicKeyParameters
        : FrodoKeyParameters
    {
        internal readonly byte[] m_publicKey;

        /// <summary>Create a new <see cref="FrodoPublicKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="publicKey">The public key.</param>
        public FrodoPublicKeyParameters(FrodoParameters parameters, byte[] publicKey)
            : base(false, parameters)
        {
            m_publicKey = Arrays.Clone(publicKey);
        }

        /// <summary>Return the public key.</summary>
        public byte[] GetPublicKey()
        {
            return Arrays.Clone(m_publicKey);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }
    }
}
