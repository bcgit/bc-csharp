namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    // TODO[api] Make sealed
    public class BcX25519Domain
        : TlsECDomain
    {
        protected readonly BcTlsCrypto m_crypto;

        public BcX25519Domain(BcTlsCrypto crypto)
        {
            m_crypto = crypto;
        }

        public virtual TlsAgreement CreateECDH()
        {
            return new BcX25519(m_crypto);
        }
    }
}
