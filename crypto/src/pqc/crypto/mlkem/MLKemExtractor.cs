using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly MLKemPrivateKeyParameters m_privateKey;
        private readonly MLKemEngine m_engine;

        public MLKemExtractor(MLKemPrivateKeyParameters privateKey)
        {
            m_privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            m_engine = m_privateKey.Parameters.GetEngine();
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] sharedSecret = new byte[m_engine.CryptoBytes];
            m_engine.KemDecrypt(sharedSecret, encapsulation, m_privateKey.GetEncoded());
            return sharedSecret;
        }

        public int EncapsulationLength => m_engine.CryptoCipherTextBytes;
    }
}
