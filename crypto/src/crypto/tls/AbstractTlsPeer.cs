using System;
namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class AbstractTlsPeer : TlsPeer
    {
        #region TlsPeer Members

        public abstract TlsCompression GetCompression();

        public abstract TlsCipher GetCipher();

        public virtual void NotifySecureRenegotiation(bool secureNegotiation)
        {
            if (!secureNegotiation)
            {
                /*
                 * RFC 5746 3.4/3.6. In this case, some clients/servers may want to terminate the handshake instead
                 * of continuing; see Section 4.1/4.3 for discussion.
                 */
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }

        public virtual void NotifyAlertRaised(AlertLevel alertLevel, AlertDescription alertDescription, string message, Exception cause)
        {
        }

        public virtual void NotifyAlertReceived(AlertLevel alertLevel, AlertDescription alertDescription)
        {
        }

        public virtual void NotifyHandshakeComplete()
        {
        }

        #endregion
    }
}
