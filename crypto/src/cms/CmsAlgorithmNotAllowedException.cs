using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    [Serializable]
    public class CmsAlgorithmNotAllowedException
        : CmsException
    {
        public CmsAlgorithmNotAllowedException()
            : base()
        {
        }

        public CmsAlgorithmNotAllowedException(string message)
            : base(message)
        {
        }

        public CmsAlgorithmNotAllowedException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CmsAlgorithmNotAllowedException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
