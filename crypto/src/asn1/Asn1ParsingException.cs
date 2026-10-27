using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Exception thrown when an ASN.1 structure cannot be parsed.</summary>
    [Serializable]
    public class Asn1ParsingException
        : InvalidOperationException
    {
        /// <summary>Create a new <see cref="Asn1ParsingException"/>.</summary>
        public Asn1ParsingException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="Asn1ParsingException"/>.</summary>
        /// <param name="message">The message.</param>
        public Asn1ParsingException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="Asn1ParsingException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public Asn1ParsingException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="Asn1ParsingException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected Asn1ParsingException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
