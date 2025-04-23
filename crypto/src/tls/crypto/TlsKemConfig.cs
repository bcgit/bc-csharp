namespace Org.BouncyCastle.Tls.Crypto
{
    public class TlsKemConfig
    {
        protected readonly int m_namedGroup;
        protected readonly bool m_isServer;

        public TlsKemConfig(int namedGroup, bool isServer)
        {
            m_namedGroup = namedGroup;
            m_isServer = isServer;
        }

        public virtual int NamedGroup => m_namedGroup;

        public virtual bool IsServer => m_isServer;
    }
}
