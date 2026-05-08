using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Common base for ML-DSA (FIPS 204) public and private key parameters; carries the
    /// <see cref="MLDsaParameters"/> selector that the key was generated for.
    /// </summary>
    public abstract class MLDsaKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly MLDsaParameters m_parameters;

        internal MLDsaKeyParameters(bool isPrivate, MLDsaParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The parameter set this key is bound to.</summary>
        public MLDsaParameters Parameters => m_parameters;
    }
}
