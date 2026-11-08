using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>XMSS^MT key-pair generation parameters.</summary>
    /// <remarks>Strength is implied by the parameter set, so the base <c>strength</c> field is left at zero.</remarks>
    public sealed class XmssMTKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly XmssMTParameters m_parameters;

        /// <param name="random">the source of the key's seeds.</param>
        /// <param name="parameters">the XMSS^MT parameter set the key pair is generated for.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="random"/> or <paramref name="parameters"/> is
        /// <c>null</c>.</exception>
        public XmssMTKeyGenerationParameters(SecureRandom random, XmssMTParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The XMSS^MT parameter set the generated key pair will be bound to.</summary>
        public XmssMTParameters Parameters => m_parameters;
    }
}
