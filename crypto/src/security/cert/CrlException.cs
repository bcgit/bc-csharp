using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    [Serializable]
    public class CrlException
        : GeneralSecurityException
    {
        /// <summary>Create a new <see cref="CrlException"/>.</summary>
        public CrlException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="CrlException"/>.</summary>
        /// <param name="message">The message.</param>
        public CrlException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="CrlException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public CrlException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CrlException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CrlException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
