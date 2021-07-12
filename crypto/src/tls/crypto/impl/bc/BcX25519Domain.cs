using System;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcX25519Domain
        : TlsECDomain
    {
        protected readonly BcTlsCrypto m_crypto;

        public BcX25519Domain(BcTlsCrypto crypto)
        {
            this.m_crypto = crypto;
        }

        public virtual TlsAgreement CreateECDH()
        {
            return new BcX25519(m_crypto);
        }
    }
}
