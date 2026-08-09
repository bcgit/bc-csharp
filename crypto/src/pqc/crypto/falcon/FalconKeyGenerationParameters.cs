using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly FalconParameters m_parameters;

        public FalconKeyGenerationParameters(SecureRandom random, FalconParameters parameters)
            : base(random, 320)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public FalconParameters Parameters => m_parameters;
    }
}
