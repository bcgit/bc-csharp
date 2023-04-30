using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public class FrodoKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly FrodoParameters m_parameters;

        public FrodoKeyGenerationParameters(SecureRandom random, FrodoParameters frodoParameters)
            : base(random, 256)
        {
            m_parameters = frodoParameters;
        }

        public FrodoParameters Parameters => m_parameters;
    }
}
