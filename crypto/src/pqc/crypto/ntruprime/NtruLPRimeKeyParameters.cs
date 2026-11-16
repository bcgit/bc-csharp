using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>Base class for NTRU LPRime keys.</summary>
    public abstract class NtruLPRimeKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly NtruLPRimeParameters m_primeParameters;

        internal NtruLPRimeKeyParameters(bool isPrivate, NtruLPRimeParameters primeParameters)
            : base(isPrivate)
        {
            m_primeParameters = primeParameters;
        }

        /// <summary>Gets the parameters.</summary>
        public NtruLPRimeParameters Parameters => m_primeParameters;
    }
}
