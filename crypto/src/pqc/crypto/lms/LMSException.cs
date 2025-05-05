using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    [Serializable]
    public class LmsException
        : Exception
    {
        public LmsException()
            : base()
        {
        }

        public LmsException(string message)
            : base(message)
        {
        }

        public LmsException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected LmsException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
