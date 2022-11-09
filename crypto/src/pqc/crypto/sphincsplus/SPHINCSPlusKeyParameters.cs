using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    public abstract class SphincsPlusKeyParameters
        : AsymmetricKeyParameter
    {
        protected readonly SphincsPlusParameters m_parameters;

        protected SphincsPlusKeyParameters(bool isPrivate, SphincsPlusParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        public SphincsPlusParameters Parameters => m_parameters;
    }
}
