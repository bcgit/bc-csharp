using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Support class for ephemeral Diffie-Hellman using the BC light-weight library.</summary>
    public class BcTlsDH
        : TlsAgreement
    {
        protected readonly BcTlsDHDomain m_domain;

        protected AsymmetricCipherKeyPair m_localKeyPair;
        protected DHPublicKeyParameters m_peerPublicKey;

        public BcTlsDH(BcTlsDHDomain domain)
        {
            this.m_domain = domain;
        }

        public virtual byte[] GenerateEphemeral()
        {
            this.m_localKeyPair = m_domain.GenerateKeyPair();

            return m_domain.EncodePublicKey((DHPublicKeyParameters)m_localKeyPair.Public);
        }

        public virtual void ReceivePeerValue(byte[] peerValue)
        {
            this.m_peerPublicKey = m_domain.DecodePublicKey(peerValue);
        }

        public virtual TlsSecret CalculateSecret()
        {
            return m_domain.CalculateDHAgreement((DHPrivateKeyParameters)m_localKeyPair.Private, m_peerPublicKey);
        }
    }
}
