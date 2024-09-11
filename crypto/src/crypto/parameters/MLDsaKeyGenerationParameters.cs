using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLDsaParameters m_parameters;

        // TODO Where does this 255 come from?
        public MLDsaKeyGenerationParameters(SecureRandom random, MLDsaParameters parameters)
            : base(random, 255)
        {
            m_parameters = parameters;
        }

        public MLDsaParameters Parameters => m_parameters;
    }
}
