using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Ocsp
{
    [Serializable]
    public class OcspException
        : Exception
    {
        public OcspException()
            : base()
        {
        }

        public OcspException(string message)
            : base(message)
        {
        }

        public OcspException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected OcspException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
