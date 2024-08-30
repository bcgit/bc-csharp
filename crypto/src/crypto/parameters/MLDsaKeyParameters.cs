using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public abstract class MLDsaKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly MLDsaParameters m_parameters;

        internal MLDsaKeyParameters(bool isPrivate, MLDsaParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public MLDsaParameters Parameters => m_parameters;
    }
}
