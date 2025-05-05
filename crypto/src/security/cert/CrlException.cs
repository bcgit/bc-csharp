using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    [Serializable]
    public class CrlException
        : GeneralSecurityException
    {
        public CrlException()
            : base()
        {
        }

        public CrlException(string message)
            : base(message)
        {
        }

        public CrlException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CrlException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
