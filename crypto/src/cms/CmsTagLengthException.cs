using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Exception thrown when an authenticated CMS content tag length is invalid.</summary>
    [Serializable]
    public class CmsTagLengthException
        : CmsException
    {
        public CmsTagLengthException()
            : base()
        {
        }

        public CmsTagLengthException(string message)
            : base(message)
        {
        }

        public CmsTagLengthException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CmsTagLengthException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
