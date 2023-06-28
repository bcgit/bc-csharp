using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    public sealed class SphincsPlusKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly SphincsPlusParameters m_parameters;

        public SphincsPlusKeyGenerationParameters(SecureRandom random, SphincsPlusParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        public SphincsPlusParameters Parameters => m_parameters;
    }
}
