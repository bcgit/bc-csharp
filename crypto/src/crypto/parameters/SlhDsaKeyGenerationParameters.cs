using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly SlhDsaParameters m_parameters;

        // TODO[pqc] Check whether 256 is meaningful
        public SlhDsaKeyGenerationParameters(SecureRandom random, SlhDsaParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        public SlhDsaParameters Parameters => m_parameters;
    }
}
