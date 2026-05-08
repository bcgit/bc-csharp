using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Common base for ML-KEM (FIPS 203) public and private key parameters; carries the
    /// <see cref="MLKemParameters"/> selector that the key was generated for.
    /// </summary>
    public abstract class MLKemKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly MLKemParameters m_parameters;

        internal MLKemKeyParameters(bool isPrivate, MLKemParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The parameter set this key is bound to.</summary>
        public MLKemParameters Parameters => m_parameters;
    }
}
