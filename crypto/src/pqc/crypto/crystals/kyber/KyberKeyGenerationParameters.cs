using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly KyberParameters m_parameters;

        public KyberKeyGenerationParameters(SecureRandom random, KyberParameters KyberParameters)
            : base(random, 256)
        {
            m_parameters = KyberParameters;
        }

        public KyberParameters Parameters => m_parameters;
    }
}
