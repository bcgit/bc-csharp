using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /// <summary>Key generation parameters for HQC, binding a randomness source to an HQC parameter set.</summary>
    public class HqcKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly HqcParameters m_parameters;

        /// <summary>Creates key generation parameters for the given HQC parameter set.</summary>
        /// <param name="random">The randomness source for key generation.</param>
        /// <param name="param">The HQC parameter set to generate keys for.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="param"/> is null.</exception>
        // TODO[api] Rename to 'parameters'
        public HqcKeyGenerationParameters(SecureRandom random, HqcParameters param)
            : base(random, 256)
        {
            m_parameters = param ?? throw new ArgumentNullException(nameof(param));
        }

        /// <summary>The HQC parameter set keys will be generated for.</summary>
        public HqcParameters Parameters => m_parameters;
    }
}
