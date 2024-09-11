using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLKemParameters m_parameters;

        public MLKemKeyGenerationParameters(SecureRandom random, MLKemParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        public MLKemParameters Parameters => m_parameters;
    }
}
