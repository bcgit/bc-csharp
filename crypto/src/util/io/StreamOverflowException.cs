using System;
using System.IO;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Utilities.IO
{
    [Serializable]
    public class StreamOverflowException
		: IOException
	{
		public StreamOverflowException()
			: base()
		{
		}

		public StreamOverflowException(string message)
			: base(message)
		{
		}

		public StreamOverflowException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected StreamOverflowException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
