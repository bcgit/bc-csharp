using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    [Obsolete("Use SLH-DSA instead")]
    public sealed class SphincsPlusKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly SphincsPlusParameters m_parameters;

        /// <summary>Create a new <see cref="SphincsPlusKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public SphincsPlusKeyGenerationParameters(SecureRandom random, SphincsPlusParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        /// <summary>Gets the parameters.</summary>
        public SphincsPlusParameters Parameters => m_parameters;
    }
}
