using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Common base for SLH-DSA public and private key parameters; carries the
    /// <see cref="SlhDsaParameters"/> selector that the key was generated for.
    /// </summary>
    public abstract class SlhDsaKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SlhDsaParameters m_parameters;

        internal SlhDsaKeyParameters(bool isPrivate, SlhDsaParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The parameter set this key is bound to.</summary>
        public SlhDsaParameters Parameters => m_parameters;
    }
}
