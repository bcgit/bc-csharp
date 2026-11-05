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
            byte[] seed = new byte[m_parameters.SecretKeyBytes];

            // the expansion key generation already did is handed to the private key so that its first
            // decapsulation does not repeat it
            byte[] expanded = m_parameters.Engine.GenKeyPair(pk, seed, m_random);

            var publicKey = new HqcPublicKeyParameters(m_parameters, pk);
            var privateKey = new HqcPrivateKeyParameters(m_parameters, seed, expanded);
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
