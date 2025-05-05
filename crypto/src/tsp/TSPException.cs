using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tsp
{
    [Serializable]
    public class TspException
        : Exception
    {
        public TspException()
            : base()
        {
        }

        public TspException(string message)
            : base(message)
        {
        }

        public TspException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TspException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
