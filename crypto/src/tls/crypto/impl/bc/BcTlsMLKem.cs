using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.MLKem;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsMLKem
        : TlsAgreement
    {
        protected readonly BcTlsMLKemDomain m_domain;

        protected MLKemPrivateKeyParameters m_privateKey;
        protected MLKemPublicKeyParameters m_publicKey;
        protected TlsSecret m_secret;

        public BcTlsMLKem(BcTlsMLKemDomain domain)
        {
            m_domain = domain;
        }

        public virtual byte[] GenerateEphemeral()
        {
            if (m_domain.IsServer)
            {
                byte[] ephemeral = m_domain.Encapsulate(m_publicKey, out m_secret);
                m_publicKey = null;
                return ephemeral;
            }
            else
            {
                AsymmetricCipherKeyPair kp = m_domain.GenerateKeyPair();
                m_privateKey = (MLKemPrivateKeyParameters)kp.Private;
                return m_domain.EncodePublicKey((MLKemPublicKeyParameters)kp.Public);
            }
        }

        public virtual void ReceivePeerValue(byte[] peerValue)
        {
            if (m_domain.IsServer)
            {
                m_publicKey = m_domain.DecodePublicKey(peerValue);
            }
            else
            {
                m_secret = m_domain.Decapsulate(m_privateKey, peerValue);
                m_privateKey = null;
            }
        }

        public virtual TlsSecret CalculateSecret()
        {
            TlsSecret secret = m_secret;
            m_secret = null;
            return secret;
        }
    }
}
