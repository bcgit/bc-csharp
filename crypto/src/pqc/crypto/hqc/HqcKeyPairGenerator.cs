using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private HqcParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((HqcKeyGenerationParameters)parameters).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            byte[] pk = new byte[m_parameters.PublicKeyBytes];
            byte[] sk = new byte[m_parameters.SecretKeyBytes];

            m_parameters.Engine.GenKeyPair(pk, sk, m_random);

            var publicKey = new HqcPublicKeyParameters(m_parameters, pk);
            var privateKey = new HqcPrivateKeyParameters(m_parameters, sk);
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
