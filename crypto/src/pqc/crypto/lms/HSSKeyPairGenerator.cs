using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private HssKeyGenerationParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_parameters = (HssKeyGenerationParameters)parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var privateKey = HssPrivateKeyParameters.Generate(m_parameters);
            var publicKey = privateKey.GetPublicKey();
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
