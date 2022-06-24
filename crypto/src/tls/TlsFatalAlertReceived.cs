using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Tls
{
    [Serializable]
    public class TlsFatalAlertReceived
        : TlsException
    {
        protected readonly short m_alertDescription;

        public TlsFatalAlertReceived(short alertDescription)
            : base(Tls.AlertDescription.GetText(alertDescription))
        {
            this.m_alertDescription = alertDescription;
        }

        protected TlsFatalAlertReceived(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public virtual short AlertDescription
        {
            get { return m_alertDescription; }
        }
    }
}
