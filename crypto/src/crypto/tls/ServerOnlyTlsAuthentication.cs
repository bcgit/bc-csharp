namespace Org.BouncyCastle.Crypto.Tls
{

    public abstract class ServerOnlyTlsAuthentication : TlsAuthentication
    {
        #region TlsAuthentication Members

        public virtual TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            return null;
        }

        public abstract void NotifyServerCertificate(Certificate serverCertificate);


        #endregion
    }

}