using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>Exception thrown on errors in LMS and HSS operations.</summary>
    // TODO[api] Make internal
    [Serializable]
    public class LmsException
        : Exception
    {
        /// <summary>Create a new <see cref="LmsException"/>.</summary>
        public LmsException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="LmsException"/>.</summary>
        /// <param name="message">The message.</param>
        public LmsException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="LmsException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public LmsException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="LmsException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected LmsException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
