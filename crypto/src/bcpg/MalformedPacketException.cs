using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Bcpg
{
    [Serializable]
    public class MalformedPacketException
        : Exception
    {
        public MalformedPacketException()
            : base()
        {
        }

        public MalformedPacketException(string message)
            : base(message)
        {
        }

        public MalformedPacketException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected MalformedPacketException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
