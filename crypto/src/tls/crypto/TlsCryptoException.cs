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
        /// <summary>Create a new <see cref="TlsCryptoException"/>.</summary>
        public TlsCryptoException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="TlsCryptoException"/>.</summary>
        /// <param name="message">The message.</param>
        public TlsCryptoException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="TlsCryptoException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public TlsCryptoException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="TlsCryptoException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TlsCryptoException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
