using System;
#if !PORTABLE
using System.Runtime.Serialization;
#endif

namespace Org.BouncyCastle.Cmp
{
    public class CmpException : Exception
    {
        public CmpException()
        {
        }

        public CmpException(string message) : base(message)
        {
        }

        public CmpException(string message, Exception innerException) : base(message, innerException)
        {
        }

#if !PORTABLE
        protected CmpException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
#endif
    }
}
