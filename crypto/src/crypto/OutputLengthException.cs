using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Exception thrown when an output buffer is too short to hold the result.</summary>
    [Serializable]
    public class OutputLengthException
        : DataLengthException
    {
        /// <summary>Create a new <see cref="OutputLengthException"/>.</summary>
        public OutputLengthException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="OutputLengthException"/>.</summary>
        /// <param name="message">The message.</param>
        public OutputLengthException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="OutputLengthException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public OutputLengthException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="OutputLengthException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected OutputLengthException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
