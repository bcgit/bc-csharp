using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>
    /// Base class for <see cref="TlsAuthentication"/> implementations of clients that do not provide a certificate.
    /// </summary>
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
