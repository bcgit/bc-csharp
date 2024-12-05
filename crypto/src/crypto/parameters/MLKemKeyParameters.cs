using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public abstract class MLKemKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly MLKemParameters m_parameters;

        internal MLKemKeyParameters(bool isPrivate, MLKemParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public MLKemParameters Parameters => m_parameters;
    }
}
