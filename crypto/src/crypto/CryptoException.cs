using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>General exception thrown for errors in cryptographic operations.</summary>
    [Serializable]
    public class CryptoException
        : Exception
    {
        /// <summary>Create a new <see cref="CryptoException"/>.</summary>
        public CryptoException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="CryptoException"/>.</summary>
        /// <param name="message">The message.</param>
        public CryptoException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="CryptoException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public CryptoException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CryptoException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CryptoException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
