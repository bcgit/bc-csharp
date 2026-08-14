using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Common base for Composite ML-DSA public and private key parameters; carries the
    /// <see cref="CompositeMLDsaParameters"/> combination the key was generated for.
    /// </summary>
    public abstract class CompositeMLDsaKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly CompositeMLDsaParameters m_parameters;

        internal CompositeMLDsaKeyParameters(bool isPrivate, CompositeMLDsaParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The combination this key is bound to.</summary>
        public CompositeMLDsaParameters Parameters => m_parameters;
    }
}
