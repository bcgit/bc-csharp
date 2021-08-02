using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Support class for ephemeral Elliptic Curve Diffie-Hellman using the BC light-weight library.</summary>
    public class BcTlsECDH
        : TlsAgreement
    {
        protected readonly BcTlsECDomain m_domain;

        protected AsymmetricCipherKeyPair m_localKeyPair;
        protected ECPublicKeyParameters m_peerPublicKey;

        public BcTlsECDH(BcTlsECDomain domain)
        {
            this.m_domain = domain;
        }

        public virtual byte[] GenerateEphemeral()
        {
            this.m_localKeyPair = m_domain.GenerateKeyPair();

            return m_domain.EncodePublicKey((ECPublicKeyParameters)m_localKeyPair.Public);
        }

        public virtual void ReceivePeerValue(byte[] peerValue)
        {
            this.m_peerPublicKey = m_domain.DecodePublicKey(peerValue);
        }

        public virtual TlsSecret CalculateSecret()
        {
            return m_domain.CalculateECDHAgreement((ECPrivateKeyParameters)m_localKeyPair.Private, m_peerPublicKey);
        }
    }
}
