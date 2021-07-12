using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Basic exception class for crypto services to pass back a cause.</summary>
    public class TlsCryptoException
        : TlsException
    {
        public TlsCryptoException(string msg)
            : base(msg)
        {
        }

        public TlsCryptoException(string msg, Exception cause)
            : base(msg, cause)
        {
        }
    }
}
