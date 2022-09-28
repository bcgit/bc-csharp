using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public class KyberKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private KyberKeyGenerationParameters m_kyberParams;
        private SecureRandom m_random;

        public void Init(KeyGenerationParameters param)
        {
            m_kyberParams = (KyberKeyGenerationParameters)param;
            m_random = param.Random;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            KyberEngine engine = m_kyberParams.Parameters.Engine;
            engine.Init(m_random);
            byte[] sk = new byte[engine.CryptoSecretKeyBytes];
            byte[] pk = new byte[engine.CryptoPublicKeyBytes];
            engine.GenerateKemKeyPair(pk, sk);

            KyberPublicKeyParameters pubKey = new KyberPublicKeyParameters(m_kyberParams.Parameters, pk);
            KyberPrivateKeyParameters privKey = new KyberPrivateKeyParameters(m_kyberParams.Parameters, sk);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
    }
}