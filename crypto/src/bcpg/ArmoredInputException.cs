using System;
using System.IO;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Bcpg
{
    [Serializable]
    public class ArmoredInputException
        : IOException
    {
        public ArmoredInputException()
            : base()
        {
        }

        public ArmoredInputException(string message)
            : base(message)
        {
        }

        public ArmoredInputException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected ArmoredInputException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
