using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    /// <summary>Exception thrown when a certificate cannot be parsed.</summary>
    [Serializable]
    public class CertificateParsingException
        : CertificateException
    {
        /// <summary>Create a new <see cref="CertificateParsingException"/>.</summary>
        public CertificateParsingException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="CertificateParsingException"/>.</summary>
        /// <param name="message">The message.</param>
        public CertificateParsingException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="CertificateParsingException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateParsingException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CertificateParsingException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CertificateParsingException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
