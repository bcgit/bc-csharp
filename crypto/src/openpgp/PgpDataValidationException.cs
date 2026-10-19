using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Thrown if the IV at the start of a data stream indicates the wrong key is being used.</summary>
    [Serializable]
    public class PgpDataValidationException
        : PgpException
    {
        /// <summary>Create a new <see cref="PgpDataValidationException"/>.</summary>
        public PgpDataValidationException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="PgpDataValidationException"/>.</summary>
        /// <param name="message">The message.</param>
        public PgpDataValidationException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="PgpDataValidationException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PgpDataValidationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PgpDataValidationException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PgpDataValidationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
