using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public sealed class FrodoPublicKeyParameters
        : FrodoKeyParameters
    {
        internal readonly byte[] m_publicKey;

        public FrodoPublicKeyParameters(FrodoParameters parameters, byte[] publicKey)
            : base(false, parameters)
        {
            m_publicKey = Arrays.Clone(publicKey);
        }

        public byte[] GetPublicKey()
        {
            return Arrays.Clone(m_publicKey);
        }

        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }
    }
}
