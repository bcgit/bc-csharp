using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>An ML-KEM key agreement for TLS, using the Bouncy Castle implementation.</summary>
    // TODO[api] Make sealed
    public class BcTlsMLKem
        : TlsAgreement
    {
        /// <summary>The domain.</summary>
        protected readonly BcTlsMLKemDomain m_domain;

        /// <summary>The private key.</summary>
        protected MLKemPrivateKeyParameters m_privateKey;
        /// <summary>The public key.</summary>
        protected MLKemPublicKeyParameters m_publicKey;
        /// <summary>The secret.</summary>
        protected TlsSecret m_secret;

        /// <summary>Create a new <see cref="BcTlsMLKem"/>.</summary>
        /// <param name="domain">The domain.</param>
        public BcTlsMLKem(BcTlsMLKemDomain domain)
        {
            m_domain = domain;
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public virtual TlsSecret CalculateSecret()
        {
            TlsSecret secret = m_secret;
            m_secret = null;
            return secret;
        }
    }
}
