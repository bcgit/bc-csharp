using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    /// <summary>A BIKE public key.</summary>
    public sealed class BikePublicKeyParameters
        : BikeKeyParameters
    {
        internal readonly byte[] m_publicKey;

        /// <summary>Create a new <see cref="BikePublicKeyParameters"/>.</summary>
        /// <param name="param">The parameters.</param>
        /// <param name="publicKey">The public key.</param>
        public BikePublicKeyParameters(BikeParameters param, byte[] publicKey)
            : base(false, param)
        {
            m_publicKey = Arrays.Clone(publicKey);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded() => Arrays.Clone(m_publicKey);
    }
}
