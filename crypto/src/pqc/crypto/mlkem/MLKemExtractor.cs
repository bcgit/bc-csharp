using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly MLKemKeyParameters m_key;
        private readonly MLKemEngine m_engine;

        public MLKemExtractor(MLKemKeyParameters privParams)
        {
            m_key = privParams;
            m_engine = m_key.Parameters.Engine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] sharedSecret = new byte[m_engine.CryptoBytes];
            m_engine.KemDecrypt(sharedSecret, encapsulation, ((MLKemPrivateKeyParameters)m_key).GetEncoded());
            return sharedSecret;
        }

        public int EncapsulationLength => m_engine.CryptoCipherTextBytes;
    }
}
