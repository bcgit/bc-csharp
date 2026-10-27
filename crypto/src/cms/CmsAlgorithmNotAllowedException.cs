using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Exception thrown when a CMS operation does not permit the requested algorithm.</summary>
    [Serializable]
    public class CmsAlgorithmNotAllowedException
        : CmsException
    {
        /// <summary>Create an exception with no detail message.</summary>
        public CmsAlgorithmNotAllowedException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public CmsAlgorithmNotAllowedException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public CmsAlgorithmNotAllowedException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CmsAlgorithmNotAllowedException"/> from serialized data.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CmsAlgorithmNotAllowedException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
