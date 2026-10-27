namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>The X25519 domain for TLS, using the Bouncy Castle implementation.</summary>
    // TODO[api] Make sealed
    public class BcX25519Domain
        : TlsECDomain
    {
        /// <summary>The crypto.</summary>
        protected readonly BcTlsCrypto m_crypto;

        /// <summary>Create a new <see cref="BcX25519Domain"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        public BcX25519Domain(BcTlsCrypto crypto)
        {
            m_crypto = crypto;
        }

        /// <inheritdoc/>
        public virtual TlsAgreement CreateECDH()
        {
            return new BcX25519(m_crypto);
        }
    }
}
