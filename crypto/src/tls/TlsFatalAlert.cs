using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Tls
{
    [Serializable]
    public class TlsFatalAlert
        : TlsException
    {
        private static string GetMessage(short alertDescription, string detailMessage)
        {
            string msg = Tls.AlertDescription.GetText(alertDescription);
            if (null != detailMessage)
            {
                msg += "; " + detailMessage;
            }
            return msg;
        }

        protected readonly short m_alertDescription;

        public TlsFatalAlert(short alertDescription)
            : this(alertDescription, (string)null)
        {
        }

        public TlsFatalAlert(short alertDescription, string detailMessage)
            : this(alertDescription, detailMessage, null)
        {
        }

        public TlsFatalAlert(short alertDescription, Exception alertCause)
            : this(alertDescription, null, alertCause)
        {
        }

        public TlsFatalAlert(short alertDescription, string detailMessage, Exception alertCause)
            : base(GetMessage(alertDescription, detailMessage), alertCause)
        {
            this.m_alertDescription = alertDescription;
        }

        protected TlsFatalAlert(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public virtual short AlertDescription
        {
            get { return m_alertDescription; }
        }
    }
}
