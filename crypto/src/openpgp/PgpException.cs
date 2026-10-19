using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generic exception class for PGP encoding/decoding problems.</summary>
    [Serializable]
    public class PgpException
        : Exception
    {
        /// <summary>Create a new <see cref="PgpException"/>.</summary>
        public PgpException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="PgpException"/>.</summary>
        /// <param name="message">The message.</param>
        public PgpException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="PgpException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PgpException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PgpException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PgpException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
