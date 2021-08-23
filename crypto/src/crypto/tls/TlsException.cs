using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class TlsException
        : IOException
    {
        public TlsException()
            : base()
        {
        }

        public TlsException(string message)
            : base(message)
        {
        }

        public TlsException(string message, Exception cause)
            : base(message, cause)
        {
        }
    }
}
