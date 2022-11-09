using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public sealed class SikeKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly SikeParameters m_parameters;

        public SikeKeyGenerationParameters(SecureRandom random, SikeParameters sikeParameters)
            : base(random, 256)
        {
            m_parameters = sikeParameters;
        }

        public SikeParameters Parameters => m_parameters;
    }
}
