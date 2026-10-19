using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>This exception is thrown whenever a cipher requires a change of key, IV or similar after x amount of
    /// bytes enciphered.
    /// </summary>
    [Serializable]
    public class MaxBytesExceededException
        : CryptoException
    {
        /// <summary>Create a new <see cref="MaxBytesExceededException"/>.</summary>
        public MaxBytesExceededException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="MaxBytesExceededException"/>.</summary>
        /// <param name="message">The message.</param>
        public MaxBytesExceededException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="MaxBytesExceededException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public MaxBytesExceededException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="MaxBytesExceededException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected MaxBytesExceededException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
