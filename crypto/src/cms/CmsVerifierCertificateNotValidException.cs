using System;
using System.Runtime.Serialization;

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

        protected CmsVerifierCertificateNotValidException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
