using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Security.Certificates
{
    [Serializable]
    public class CertificateExpiredException
		: CertificateException
	{
		public CertificateExpiredException()
			: base()
		{
		}

		public CertificateExpiredException(string message)
			: base(message)
		{
		}

		public CertificateExpiredException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected CertificateExpiredException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
