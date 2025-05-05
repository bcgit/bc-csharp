using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    [Serializable]
    public class GeneralSecurityException
        : Exception
    {
        public GeneralSecurityException()
            : base()
        {
        }

        public GeneralSecurityException(string message)
            : base(message)
        {
        }

        public GeneralSecurityException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected GeneralSecurityException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
