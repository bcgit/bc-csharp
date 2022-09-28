using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly KyberKeyParameters m_key;
        private readonly KyberEngine m_engine;

        public KyberKemExtractor(KyberKeyParameters privParams)
        {
            m_key = privParams;
            m_engine = m_key.Parameters.Engine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] sessionKey = new byte[m_engine.CryptoBytes];
            m_engine.KemDecrypt(sessionKey, encapsulation, ((KyberPrivateKeyParameters)m_key).m_privateKey);
            byte[] rv = Arrays.CopyOfRange(sessionKey, 0, m_key.Parameters.DefaultKeySize / 8);
            Arrays.Clear(sessionKey);
            return rv;
        }

        public int EncapsulationLength => m_engine.CryptoCipherTextBytes;
    }
}
