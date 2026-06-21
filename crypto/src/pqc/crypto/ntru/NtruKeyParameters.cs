using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>Base class for NTRU public and private keys, carrying the associated parameter set.</summary>
    public abstract class NtruKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly NtruParameters m_parameters;

        internal NtruKeyParameters(bool privateKey, NtruParameters parameters)
            : base(privateKey)
        {
            m_parameters = parameters;
        }

        /// <summary>The NTRU parameter set this key belongs to.</summary>
        public NtruParameters Parameters => m_parameters;

        /// <summary>Returns a copy of the raw key encoding.</summary>
        public abstract byte[] GetEncoded();
    }
}
