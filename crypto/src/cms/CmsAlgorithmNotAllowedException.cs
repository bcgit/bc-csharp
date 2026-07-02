using System;
using System.Runtime.Serialization;

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

        protected CmsAlgorithmNotAllowedException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
