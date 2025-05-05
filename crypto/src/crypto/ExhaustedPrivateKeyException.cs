using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Exception thrown by a stateful signature algorithm when the private key counter is exhausted.
    /// </summary>
    [Serializable]
    public class ExhaustedPrivateKeyException
        : InvalidOperationException
    {
        public ExhaustedPrivateKeyException()
            : base()
        {
        }

        public ExhaustedPrivateKeyException(string message)
            : base(message)
        {
        }

        public ExhaustedPrivateKeyException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected ExhaustedPrivateKeyException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
