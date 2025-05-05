using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
    [Serializable]
    public class CryptoException
		: Exception
    {
		public CryptoException()
			: base()
		{
		}

		public CryptoException(string message)
			: base(message)
		{
		}

		public CryptoException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected CryptoException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
