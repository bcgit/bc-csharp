using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly HqcParameters m_parameters;

        // TODO[api] Rename to 'parameters'
        public HqcKeyGenerationParameters(SecureRandom random, HqcParameters param)
            : base(random, 256)
        {
            m_parameters = param ?? throw new ArgumentNullException(nameof(param));
        }

        public HqcParameters Parameters => m_parameters;
    }
}
