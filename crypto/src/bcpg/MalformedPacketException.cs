using System;
using System.IO;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Bcpg
{
    [Serializable]
    public class MalformedPacketException
        : IOException
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
