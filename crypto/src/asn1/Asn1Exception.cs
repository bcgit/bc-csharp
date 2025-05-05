using System;
using System.IO;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Asn1
{
    [Serializable]
    public class Asn1Exception
		: IOException
	{
		public Asn1Exception()
			: base()
		{
		}

		public Asn1Exception(string message)
			: base(message)
		{
		}

		public Asn1Exception(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected Asn1Exception(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
