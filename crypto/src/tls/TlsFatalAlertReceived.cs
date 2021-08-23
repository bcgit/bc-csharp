using System;

namespace Org.BouncyCastle.Tls
{
    public class TlsFatalAlertReceived
        : TlsException
    {
        protected readonly short m_alertDescription;

        public TlsFatalAlertReceived(short alertDescription)
            : base(Tls.AlertDescription.GetText(alertDescription))
        {
            this.m_alertDescription = alertDescription;
        }

        public virtual short AlertDescription
        {
            get { return m_alertDescription; }
        }
    }
}
