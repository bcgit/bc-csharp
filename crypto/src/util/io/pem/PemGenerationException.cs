using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
    [Serializable]
    public class PemGenerationException
        : Exception
    {
        /// <summary>Create a new <see cref="PemGenerationException"/>.</summary>
        public PemGenerationException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="PemGenerationException"/>.</summary>
        /// <param name="message">The message.</param>
        public PemGenerationException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="PemGenerationException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PemGenerationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PemGenerationException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PemGenerationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
