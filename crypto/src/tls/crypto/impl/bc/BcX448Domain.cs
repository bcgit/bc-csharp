namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>The X448 domain for TLS, using the Bouncy Castle implementation.</summary>
    // TODO[api] Make sealed
    public class BcX448Domain
        : TlsECDomain
    {
        protected readonly BcTlsCrypto m_crypto;

        /// <summary>Create a new <see cref="BcX448Domain"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        public BcX448Domain(BcTlsCrypto crypto)
        {
            m_crypto = crypto;
        }

        /// <inheritdoc/>
        public virtual TlsAgreement CreateECDH()
        {
            return new BcX448(m_crypto);
        }
    }
}
