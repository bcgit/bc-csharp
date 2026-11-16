using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Exception thrown when an authenticated CMS content tag length is invalid.</summary>
    [Serializable]
    public class CmsTagLengthException
        : CmsException
    {
        /// <summary>Create an exception with no detail message.</summary>
        public CmsTagLengthException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public CmsTagLengthException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public CmsTagLengthException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="CmsTagLengthException"/> from serialized data.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CmsTagLengthException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
