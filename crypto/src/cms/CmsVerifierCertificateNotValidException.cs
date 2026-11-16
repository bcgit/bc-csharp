using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Exception thrown when a signer certificate is not valid at the signing time.</summary>
    [Serializable]
    public class CmsVerifierCertificateNotValidException
        : CmsException
    {
        /// <summary>Create an exception with no detail message.</summary>
        public CmsVerifierCertificateNotValidException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public CmsVerifierCertificateNotValidException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public CmsVerifierCertificateNotValidException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CmsVerifierCertificateNotValidException"/> from serialized data.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CmsVerifierCertificateNotValidException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
