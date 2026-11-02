using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    /// <summary>Base class for FrodoKEM keys.</summary>
    public abstract class FrodoKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly FrodoParameters m_parameters;

        internal FrodoKeyParameters(bool isPrivate, FrodoParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        /// <summary>Gets the parameters.</summary>
        public FrodoParameters Parameters => m_parameters;
    }
}
