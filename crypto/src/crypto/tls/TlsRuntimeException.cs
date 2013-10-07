namespace Org.BouncyCastle.Crypto.Tls
{
    using System;

    public class TlsRuntimeException : Exception
    {
        private const long serialVersionUID = 1928023487348344086L;

        public TlsRuntimeException(string message, Exception e)
            : base(message, e)
        {

        }

        public TlsRuntimeException(string message)
            : base(message)
        {

        }
    }
}