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

        public KyberPrivateKeyParameters(KyberParameters parameters, byte[] encoding)
            : base(true, parameters)
        {
            KyberEngine eng = parameters.Engine;

            int index = 0;
            m_s = Arrays.CopyOfRange(encoding, 0, eng.IndCpaSecretKeyBytes); index += eng.IndCpaSecretKeyBytes;
            m_t = Arrays.CopyOfRange(encoding, index, index + eng.IndCpaPublicKeyBytes - KyberEngine.SymBytes); index += eng.IndCpaPublicKeyBytes - KyberEngine.SymBytes;
            m_rho = Arrays.CopyOfRange(encoding, index, index + 32); index += 32;
            m_hpk = Arrays.CopyOfRange(encoding, index, index + 32); index += 32;
            m_nonce = Arrays.CopyOfRange(encoding, index, index + KyberEngine.SymBytes);       
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
