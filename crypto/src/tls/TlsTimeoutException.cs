using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    public class TlsTimeoutException
        : IOException
    {
        public TlsTimeoutException()
            : base()
        {
        }

        public TlsTimeoutException(string message)
            : base(message)
        {
        }

        public TlsTimeoutException(string message, Exception cause)
            : base(message, cause)
        {
        }
    }
}
