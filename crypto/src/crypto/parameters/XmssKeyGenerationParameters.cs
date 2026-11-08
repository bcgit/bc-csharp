using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>XMSS key-pair generation parameters.</summary>
    /// <remarks>Strength is implied by the parameter set, so the base <c>strength</c> field is left at zero.</remarks>
    public sealed class XmssKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly XmssParameters m_parameters;

        /// <param name="random">the source of the key's seeds.</param>
        /// <param name="parameters">the XMSS parameter set the key pair is generated for.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="random"/> or <paramref name="parameters"/> is
        /// <c>null</c>.</exception>
        public XmssKeyGenerationParameters(SecureRandom random, XmssParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The XMSS parameter set the generated key pair will be bound to.</summary>
        public XmssParameters Parameters => m_parameters;
    }
}
