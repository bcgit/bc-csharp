using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>A generator of HSS key pairs.</summary>
    public sealed class HssKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private HssKeyGenerationParameters m_parameters;

        /// <inheritdoc/>
        public void Init(KeyGenerationParameters parameters)
        {
            m_parameters = (HssKeyGenerationParameters)parameters;
        }

        /// <inheritdoc/>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var privateKey = HssPrivateKeyParameters.Generate(m_parameters);
            var publicKey = privateKey.GetPublicKey();
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
