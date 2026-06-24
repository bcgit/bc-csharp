using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /// <summary>Base class for HQC public and private keys, carrying the associated parameter set.</summary>
    public abstract class HqcKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly HqcParameters m_parameters;

        internal HqcKeyParameters(bool isPrivate, HqcParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        /// <summary>The HQC parameter set this key belongs to.</summary>
        public HqcParameters Parameters => m_parameters;
    }
}
