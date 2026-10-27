using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>This exception is thrown if a buffer that is meant to have output copied into it turns out to be too
    /// short, or if we've been given insufficient input.</summary>
    /// <remarks>
    /// In general this exception will get thrown rather than an <see cref="IndexOutOfRangeException"/>.
    /// </remarks>
    [Serializable]
    public class DataLengthException
        : CryptoException
    {
        /// <summary>Create a new <see cref="DataLengthException"/>.</summary>
        public DataLengthException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="DataLengthException"/>.</summary>
        /// <param name="message">The message.</param>
        public DataLengthException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="DataLengthException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public DataLengthException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="DataLengthException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected DataLengthException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
