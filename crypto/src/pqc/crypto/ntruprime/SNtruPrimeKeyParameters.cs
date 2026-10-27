using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>Base class for Streamlined NTRU Prime keys.</summary>
    public abstract class SNtruPrimeKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SNtruPrimeParameters m_primeParameters;

        internal SNtruPrimeKeyParameters(bool isPrivate, SNtruPrimeParameters primeParameters)
            : base(isPrivate)
        {
            m_primeParameters = primeParameters;
        }

        /// <summary>Gets the parameters.</summary>
        public SNtruPrimeParameters Parameters => m_primeParameters;
    }
}
