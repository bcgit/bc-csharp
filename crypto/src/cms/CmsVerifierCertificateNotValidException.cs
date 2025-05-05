using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    [Serializable]
    public class CmsVerifierCertificateNotValidException
        : CmsException
    {
        public CmsVerifierCertificateNotValidException()
            : base()
        {
        }

        public CmsVerifierCertificateNotValidException(string message)
            : base(message)
        {
        }

        public CmsVerifierCertificateNotValidException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CmsVerifierCertificateNotValidException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
