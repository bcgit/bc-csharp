using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    [Serializable]
    public class CertificateParsingException
        : CertificateException
    {
        public CertificateParsingException()
            : base()
        {
        }

        public CertificateParsingException(string message)
            : base(message)
        {
        }

        public CertificateParsingException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CertificateParsingException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
