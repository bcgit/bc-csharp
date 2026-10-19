using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    /// <summary>Base class for certificate-related exceptions.</summary>
    [Serializable]
    public class CertificateException
        : GeneralSecurityException
    {
        /// <summary>Create a new <see cref="CertificateException"/>.</summary>
        public CertificateException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="CertificateException"/>.</summary>
        /// <param name="message">The message.</param>
        public CertificateException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="CertificateException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CertificateException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CertificateException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
