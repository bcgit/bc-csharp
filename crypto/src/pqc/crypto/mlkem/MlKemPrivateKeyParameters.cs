using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemPrivateKeyParameters
        : MLKemKeyParameters
    {
        private readonly byte[] m_s;
        private readonly byte[] m_hpk;
        private readonly byte[] m_nonce;
        private readonly byte[] m_t;
        private readonly byte[] m_rho;

        public MLKemPrivateKeyParameters(MLKemParameters parameters, byte[] encoding)
            : base(true, parameters)
        {
            MLKemEngine eng = parameters.Engine;

            int index = 0;
            m_s = Arrays.CopyOfRange(encoding, 0, eng.IndCpaSecretKeyBytes); index += eng.IndCpaSecretKeyBytes;
            m_t = Arrays.CopyOfRange(encoding, index, index + eng.IndCpaPublicKeyBytes - MLKemEngine.SymBytes); index += eng.IndCpaPublicKeyBytes - MLKemEngine.SymBytes;
            m_rho = Arrays.CopyOfRange(encoding, index, index + 32); index += 32;
            m_hpk = Arrays.CopyOfRange(encoding, index, index + 32); index += 32;
            m_nonce = Arrays.CopyOfRange(encoding, index, index + MLKemEngine.SymBytes);       
        }

        internal MLKemPrivateKeyParameters(MLKemParameters parameters, byte[] s, byte[] hpk, byte[] nonce, byte[] t,
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

        internal byte[] GetHpk() => Arrays.Clone(m_hpk);

        internal byte[] GetNonce() => Arrays.Clone(m_nonce);

        public byte[] GetPublicKey() => MLKemPublicKeyParameters.GetEncoded(m_t, m_rho);

        public MLKemPublicKeyParameters GetPublicKeyParameters() =>
            new MLKemPublicKeyParameters(Parameters, m_t, m_rho);

        internal byte[] GetRho() => Arrays.Clone(m_rho);

        internal byte[] GetS() => Arrays.Clone(m_s);

        internal byte[] GetT() => Arrays.Clone(m_t);
    }
}
