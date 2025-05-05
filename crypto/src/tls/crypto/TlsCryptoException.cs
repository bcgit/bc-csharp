using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Basic exception class for crypto services to pass back a cause.</summary>
    [Serializable]
    public class TlsCryptoException
        : TlsException
    {
        public TlsCryptoException()
            : base()
        {
        }

        public TlsCryptoException(string message)
            : base(message)
        {
        }

        public TlsCryptoException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TlsCryptoException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
