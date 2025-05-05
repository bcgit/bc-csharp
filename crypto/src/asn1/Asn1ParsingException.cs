using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    [Serializable]
    public class Asn1ParsingException
        : InvalidOperationException
    {
        public Asn1ParsingException()
            : base()
        {
        }

        public Asn1ParsingException(string message)
            : base(message)
        {
        }

        public Asn1ParsingException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected Asn1ParsingException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
