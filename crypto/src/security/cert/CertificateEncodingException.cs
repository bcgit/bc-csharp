using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Certificates
{
    [Serializable]
    public class CertificateEncodingException
        : CertificateException
    {
        public CertificateEncodingException()
            : base()
        {
        }

        public CertificateEncodingException(string message)
            : base(message)
        {
        }

        public CertificateEncodingException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CertificateEncodingException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
