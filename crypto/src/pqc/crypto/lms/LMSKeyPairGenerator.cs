using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>A generator of LMS key pairs.</summary>
    public sealed class LmsKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private LmsKeyGenerationParameters m_parameters;

        /// <inheritdoc/>
        public void Init(KeyGenerationParameters parameters)
        {
            m_parameters = (LmsKeyGenerationParameters)parameters;
        }

        /// <inheritdoc/>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var privateKey = LmsPrivateKeyParameters.Generate(m_parameters.LmsParameters, m_parameters.Random);
            var publicKey = privateKey.GetPublicKey();
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
