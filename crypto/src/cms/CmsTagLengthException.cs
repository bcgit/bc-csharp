using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Cms
{
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

        protected CmsTagLengthException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
