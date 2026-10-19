using System;

namespace Org.BouncyCastle.Tls
{
    public abstract class ServerOnlyTlsAuthentication
        : TlsAuthentication
    {
        /// <inheritdoc/>
        public abstract void NotifyServerCertificate(TlsServerCertificate serverCertificate);

        /// <inheritdoc/>
        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            return null;
        }
    }
}
