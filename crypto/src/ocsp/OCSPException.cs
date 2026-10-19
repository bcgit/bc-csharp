using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Exception thrown when an OCSP request or response cannot be processed.</summary>
    [Serializable]
    public class OcspException
        : Exception
    {
        /// <summary>Create a new <see cref="OcspException"/>.</summary>
        public OcspException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="OcspException"/>.</summary>
        /// <param name="message">The message.</param>
        public OcspException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="OcspException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public OcspException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="OcspException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected OcspException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
