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

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected LmsException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
