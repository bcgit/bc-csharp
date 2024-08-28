using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemPublicKeyParameters
        : MLKemKeyParameters
    {
        internal static byte[] GetEncoded(byte[] t, byte[] rho) => Arrays.Concatenate(t, rho);

        private readonly byte[] m_t;
        private readonly byte[] m_rho;

        public MLKemPublicKeyParameters(MLKemParameters parameters, byte[] t, byte[] rho)
            : base(false, parameters)
        {
            m_t = Arrays.Clone(t);
            m_rho = Arrays.Clone(rho);
        }

        public MLKemPublicKeyParameters(MLKemParameters parameters, byte[] encoding)
            : base(false, parameters)
        {
            m_t = Arrays.CopyOfRange(encoding, 0, encoding.Length - MLKemEngine.SymBytes);
            m_rho = Arrays.CopyOfRange(encoding, encoding.Length - MLKemEngine.SymBytes, encoding.Length);
        }

        public byte[] GetEncoded() => GetEncoded(m_t, m_rho);

        public byte[] GetRho() => Arrays.Clone(m_rho);

        public byte[] GetT() => Arrays.Clone(m_t);
    }
}
    