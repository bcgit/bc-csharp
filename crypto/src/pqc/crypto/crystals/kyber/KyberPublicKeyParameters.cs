using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberPublicKeyParameters
        : KyberKeyParameters
    {
        internal readonly byte[] m_publicKey;

        public KyberPublicKeyParameters(KyberParameters parameters, byte[] publicKey)
            : base(false, parameters)
        {
            m_publicKey = Arrays.Clone(publicKey);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(m_publicKey);
        }
    }
}
