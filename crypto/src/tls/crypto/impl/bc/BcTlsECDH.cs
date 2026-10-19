using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Support class for ephemeral Elliptic Curve Diffie-Hellman using the BC light-weight library.</summary>
    // TODO[api] Make sealed
    public class BcTlsECDH
        : TlsAgreement
    {
        protected readonly BcTlsECDomain m_domain;

        /// <summary>The local key pair.</summary>
        protected AsymmetricCipherKeyPair m_localKeyPair;
        /// <summary>The peer public key.</summary>
        protected ECPublicKeyParameters m_peerPublicKey;

        /// <summary>Create a new <see cref="BcTlsECDH"/>.</summary>
        /// <param name="domain">The domain.</param>
        public BcTlsECDH(BcTlsECDomain domain)
        {
            m_domain = domain;
        }

        /// <inheritdoc/>
        public virtual byte[] GenerateEphemeral()
        {
            m_localKeyPair = m_domain.GenerateKeyPair();

            return m_domain.EncodePublicKey((ECPublicKeyParameters)m_localKeyPair.Public);
        }

        /// <inheritdoc/>
        public virtual void ReceivePeerValue(byte[] peerValue)
        {
            m_peerPublicKey = m_domain.DecodePublicKey(peerValue);
        }

        /// <inheritdoc/>
        public virtual TlsSecret CalculateSecret()
        {
            return m_domain.CalculateECDHAgreement((ECPrivateKeyParameters)m_localKeyPair.Private, m_peerPublicKey);
        }
    }
}
