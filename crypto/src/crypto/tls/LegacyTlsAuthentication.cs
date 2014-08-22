using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <summary>
    /// A temporary class to wrap old CertificateVerifyer stuff for new TlsAuthentication.
    /// </summary>
    [Obsolete]
    public class LegacyTlsAuthentication
        :   ServerOnlyTlsAuthentication
    {
        protected ICertificateVerifyer verifyer;

        public LegacyTlsAuthentication(ICertificateVerifyer verifyer)
        {
            this.verifyer = verifyer;
        }

        public override void NotifyServerCertificate(Certificate serverCertificate)
        {
            if (!this.verifyer.IsValid(serverCertificate.GetCertificateList()))
                throw new TlsFatalAlert(AlertDescription.user_canceled);
        }
    }
}
