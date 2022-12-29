using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public abstract class PicnicKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly PicnicParameters m_parameters;

        internal PicnicKeyParameters(bool isPrivate, PicnicParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        public PicnicParameters Parameters => m_parameters;
    }
}
