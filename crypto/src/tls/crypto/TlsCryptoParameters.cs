namespace Org.BouncyCastle.Tls.Crypto
{
    // TODO[api] Make sealed
    /// <summary>Carrier class for context-related parameters needed for creating secrets and ciphers.</summary>
    public class TlsCryptoParameters
    {
        private readonly TlsContext m_context;

        /// <summary>Base constructor.</summary>
        /// <param name="context">the context for this parameters object.</param>
        public TlsCryptoParameters(TlsContext context)
        {
            m_context = context;
        }

        public SecurityParameters SecurityParameters => m_context.SecurityParameters;

        /// <summary>Gets the client version.</summary>
        public ProtocolVersion ClientVersion => m_context.ClientVersion;

        /// <summary>Gets the rsa pre master secret version.</summary>
        public ProtocolVersion RsaPreMasterSecretVersion => m_context.RsaPreMasterSecretVersion;

        /// <summary>Gets the server version.</summary>
        // TODO[api] Make non-virtual
        public virtual ProtocolVersion ServerVersion => m_context.ServerVersion;

        /// <summary>Gets a value indicating whether this is server.</summary>
        public bool IsServer => m_context.IsServer;

        /// <summary>Gets the nonce generator.</summary>
        public TlsNonceGenerator NonceGenerator => m_context.NonceGenerator;
    }
}
