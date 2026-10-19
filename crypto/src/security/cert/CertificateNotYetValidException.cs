using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    /// <summary>Exception thrown when a certificate is not yet valid.</summary>
    [Serializable]
    public class CertificateNotYetValidException
        : CertificateException
    {
        /// <summary>Create a new <see cref="CertificateNotYetValidException"/>.</summary>
        public CertificateNotYetValidException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="CertificateNotYetValidException"/>.</summary>
        /// <param name="message">The message.</param>
        public CertificateNotYetValidException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="CertificateNotYetValidException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateNotYetValidException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CertificateNotYetValidException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CertificateNotYetValidException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
