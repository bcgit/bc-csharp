namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>The configuration of a KEM used in a TLS key exchange.</summary>
    public class TlsKemConfig
    {
        /// <summary>The named group.</summary>
        protected readonly int m_namedGroup;
        /// <summary>The is server.</summary>
        protected readonly bool m_isServer;

        /// <summary>Create a new <see cref="TlsKemConfig"/>.</summary>
        /// <param name="namedGroup">The named group.</param>
        /// <param name="isServer">true if is server, false otherwise.</param>
        public TlsKemConfig(int namedGroup, bool isServer)
        {
            m_namedGroup = namedGroup;
            m_isServer = isServer;
        }

        /// <summary>Gets the named group.</summary>
        public virtual int NamedGroup => m_namedGroup;

        /// <summary>Gets a value indicating whether this is server.</summary>
        public virtual bool IsServer => m_isServer;
    }
}
