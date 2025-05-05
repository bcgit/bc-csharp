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
        public PgpKeyValidationException()
            : base()
        {
        }

        public PgpKeyValidationException(string message)
            : base(message)
        {
        }

        public PgpKeyValidationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PgpKeyValidationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
