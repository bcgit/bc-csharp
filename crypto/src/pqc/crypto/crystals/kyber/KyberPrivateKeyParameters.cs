using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberPrivateKeyParameters
        : KyberKeyParameters
    {
        internal readonly byte[] m_privateKey;

        public KyberPrivateKeyParameters(KyberParameters parameters, byte[] privateKey)
            : base(true, parameters)
        {
            m_privateKey = Arrays.Clone(privateKey);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(m_privateKey);
        }
    }
}
