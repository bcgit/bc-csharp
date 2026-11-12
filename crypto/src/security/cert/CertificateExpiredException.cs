using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    /// <summary>Exception thrown when a certificate has expired.</summary>
    [Serializable]
    public class CertificateExpiredException
        : CertificateException
    {
        /// <summary>Create a new <see cref="CertificateExpiredException"/>.</summary>
        public CertificateExpiredException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="CertificateExpiredException"/>.</summary>
        /// <param name="message">The message.</param>
        public CertificateExpiredException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="CertificateExpiredException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateExpiredException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CertificateExpiredException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CertificateExpiredException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
