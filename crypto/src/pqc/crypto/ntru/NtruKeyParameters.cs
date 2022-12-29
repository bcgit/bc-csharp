using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    public abstract class NtruKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly NtruParameters m_parameters;

        internal NtruKeyParameters(bool privateKey, NtruParameters parameters)
            : base(privateKey)
        {
            m_parameters = parameters;
        }

        public NtruParameters Parameters => m_parameters;

        public abstract byte[] GetEncoded();
    }
}
