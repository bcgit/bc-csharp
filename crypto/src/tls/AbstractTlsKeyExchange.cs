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

        protected AbstractTlsKeyExchange(int keyExchange)
        {
            m_keyExchange = keyExchange;
        }

        public virtual void Init(TlsContext context)
        {
            m_context = context;
        }

        public abstract void SkipServerCredentials();

        public abstract void ProcessServerCredentials(TlsCredentials serverCredentials);

        public virtual void ProcessServerCertificate(Certificate serverCertificate) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        public virtual bool RequiresServerKeyExchange => false;

        public virtual byte[] GenerateServerKeyExchange()
        {
            if (RequiresServerKeyExchange)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return null;
        }

        public virtual void SkipServerKeyExchange()
        {
            if (RequiresServerKeyExchange)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public virtual void ProcessServerKeyExchange(Stream input)
        {
            if (!RequiresServerKeyExchange)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public virtual short[] GetClientCertificateTypes() => null;

        public virtual void SkipClientCredentials() {}

        public abstract void ProcessClientCredentials(TlsCredentials clientCredentials);

        public virtual void ProcessClientCertificate(Certificate clientCertificate) {}

        public abstract void GenerateClientKeyExchange(Stream output);

        // Key exchange implementation MUST support client key exchange
        public virtual void ProcessClientKeyExchange(Stream input) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        public virtual bool RequiresCertificateVerify => true;

        public abstract TlsSecret GeneratePreMasterSecret();
    }
}
