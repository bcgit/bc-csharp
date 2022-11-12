using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public abstract class FrodoKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly FrodoParameters m_parameters;

        internal FrodoKeyParameters(bool isPrivate, FrodoParameters parameters)
            : base(isPrivate)
        {
            this.m_parameters = parameters;
        }

        public FrodoParameters Parameters => m_parameters;
    }
}
