using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Thrown if the key checksum is invalid.</summary>
    [Serializable]
    public class PgpKeyValidationException
        : PgpException
    {
        /// <summary>Create a new <see cref="PgpKeyValidationException"/>.</summary>
        public PgpKeyValidationException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="PgpKeyValidationException"/>.</summary>
        /// <param name="message">The message.</param>
        public PgpKeyValidationException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="PgpKeyValidationException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PgpKeyValidationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PgpKeyValidationException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PgpKeyValidationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
