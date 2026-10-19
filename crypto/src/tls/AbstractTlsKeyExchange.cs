using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base class for supporting a TLS key exchange implementation.</summary>
    public abstract class AbstractTlsKeyExchange
        : TlsKeyExchange
    {
        protected readonly int m_keyExchange;

        protected TlsContext m_context;

        /// <summary>Create a new <see cref="AbstractTlsKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        protected AbstractTlsKeyExchange(int keyExchange)
        {
            m_keyExchange = keyExchange;
        }

        /// <inheritdoc/>
        public virtual void Init(TlsContext context)
        {
            m_context = context;
        }

        /// <inheritdoc/>
        public abstract void SkipServerCredentials();

        /// <inheritdoc/>
        public abstract void ProcessServerCredentials(TlsCredentials serverCredentials);

        /// <inheritdoc/>
        public virtual void ProcessServerCertificate(Certificate serverCertificate) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public virtual bool RequiresServerKeyExchange => false;

        /// <inheritdoc/>
        public virtual byte[] GenerateServerKeyExchange()
        {
            if (RequiresServerKeyExchange)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return null;
        }

        /// <inheritdoc/>
        public virtual void SkipServerKeyExchange()
        {
            if (RequiresServerKeyExchange)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        /// <inheritdoc/>
        public virtual void ProcessServerKeyExchange(Stream input)
        {
            if (!RequiresServerKeyExchange)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        /// <inheritdoc/>
        public virtual short[] GetClientCertificateTypes() => null;

        /// <inheritdoc/>
        public virtual void SkipClientCredentials() {}

        /// <inheritdoc/>
        public abstract void ProcessClientCredentials(TlsCredentials clientCredentials);

        /// <inheritdoc/>
        public virtual void ProcessClientCertificate(Certificate clientCertificate) {}

        /// <inheritdoc/>
        public abstract void GenerateClientKeyExchange(Stream output);

        /// <inheritdoc/>
        // Key exchange implementation MUST support client key exchange
        public virtual void ProcessClientKeyExchange(Stream input) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public virtual bool RequiresCertificateVerify => true;

        /// <inheritdoc/>
        public abstract TlsSecret GeneratePreMasterSecret();
    }
}
