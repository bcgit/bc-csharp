using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class TlsFatalAlert
        : IOException
    {
        private readonly byte alertDescription;

        public TlsFatalAlert(byte alertDescription)
        {
            this.alertDescription = alertDescription;
        }

        public virtual byte AlertDescription
        {
            get { return alertDescription; }
        }
    }
}
