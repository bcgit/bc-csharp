using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    [Serializable]
    public class LmsException
        : Exception
    {
		public LmsException()
			: base()
		{
		}

		public LmsException(string message)
			: base(message)
		{
		}

		public LmsException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected LmsException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
