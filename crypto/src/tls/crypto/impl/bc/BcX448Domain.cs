using System;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcX448Domain
        : TlsECDomain
    {
        protected readonly BcTlsCrypto m_crypto;

        public BcX448Domain(BcTlsCrypto crypto)
        {
            this.m_crypto = crypto;
        }

        public virtual TlsAgreement CreateECDH()
        {
            return new BcX448(m_crypto);
        }
    }
}
