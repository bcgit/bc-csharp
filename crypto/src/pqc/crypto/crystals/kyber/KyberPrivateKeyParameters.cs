using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberPrivateKeyParameters
        : KyberKeyParameters
    {
        private readonly byte[] m_s;
        private readonly byte[] m_hpk;
        private readonly byte[] m_nonce;
        private readonly byte[] m_t;
        private readonly byte[] m_rho;

        public KyberPrivateKeyParameters(KyberParameters parameters, byte[] s, byte[] hpk, byte[] nonce, byte[] t,
            byte[] rho)
            : base(true, parameters)
        {
            m_s = Arrays.Clone(s);
            m_hpk = Arrays.Clone(hpk);
            m_nonce = Arrays.Clone(nonce);
            m_t = Arrays.Clone(t);
            m_rho = Arrays.Clone(rho);
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_s, m_t, m_rho, m_hpk, m_nonce);

        public byte[] GetHpk() => Arrays.Clone(m_hpk);

        public byte[] GetNonce() => Arrays.Clone(m_nonce);

        public byte[] GetPublicKey() => KyberPublicKeyParameters.GetEncoded(m_t, m_rho);

        public KyberPublicKeyParameters GetPublicKeyParameters() =>
            new KyberPublicKeyParameters(Parameters, m_t, m_rho);

        public byte[] GetRho() => Arrays.Clone(m_rho);

        public byte[] GetS() => Arrays.Clone(m_s);

        public byte[] GetT() => Arrays.Clone(m_t);
    }
}
