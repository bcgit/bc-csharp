using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikePublicKeyParameters
        : BikeKeyParameters
    {
        internal readonly byte[] m_publicKey;

        public BikePublicKeyParameters(BikeParameters param, byte[] publicKey)
            : base(false, param)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.Length != param.RByte)
                throw new ArgumentException("Invalid length", nameof(publicKey));

            m_publicKey = Arrays.Clone(publicKey);
        }

        public byte[] GetEncoded() => Arrays.Clone(m_publicKey);
    }
}
