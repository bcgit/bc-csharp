using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>Exception thrown when a time stamp request, response or token cannot be processed.</summary>
    [Serializable]
    public class TspException
        : Exception
    {
        /// <summary>Create a new <see cref="TspException"/>.</summary>
        public TspException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="TspException"/>.</summary>
        /// <param name="message">The message.</param>
        public TspException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="TspException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public TspException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="TspException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TspException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
