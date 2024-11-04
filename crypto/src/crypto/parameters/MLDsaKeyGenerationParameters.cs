using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLDsaParameters m_parameters;

        public MLDsaKeyGenerationParameters(SecureRandom random, MLDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters;
        }

        public MLDsaParameters Parameters => m_parameters;
    }
}
