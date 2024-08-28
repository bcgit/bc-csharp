using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public abstract class MLKemKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly MLKemParameters m_parameters;

        internal MLKemKeyParameters(bool isPrivate, MLKemParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        public MLKemParameters Parameters => m_parameters;
    }
}
