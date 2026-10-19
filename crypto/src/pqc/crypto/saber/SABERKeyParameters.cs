using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public abstract class SaberKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SaberParameters m_parameters;

        internal SaberKeyParameters(bool isPrivate, SaberParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        /// <summary>Gets the parameters.</summary>
        public SaberParameters Parameters => m_parameters;
    }
}
