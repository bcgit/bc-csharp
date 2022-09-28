using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberPublicKeyParameters
        : KyberKeyParameters
    {
        private readonly byte[] m_t;
        private readonly byte[] m_rho;

        public byte[] GetEncoded()
        {
            return Arrays.Concatenate(m_t, m_rho);
        }

        public KyberPublicKeyParameters(KyberParameters parameters, byte[] encoding)
            : base(false, parameters)
        {
            m_t = Arrays.CopyOfRange(encoding, 0, encoding.Length - KyberEngine.SymBytes);
            m_rho = Arrays.CopyOfRange(encoding, encoding.Length - KyberEngine.SymBytes, encoding.Length);
        }

        public KyberPublicKeyParameters(KyberParameters parameters, byte[] t, byte[] rho)
            : base(false, parameters)
        {
            m_t = Arrays.Clone(t);
            m_rho = Arrays.Clone(rho);
        }
    }
}
    