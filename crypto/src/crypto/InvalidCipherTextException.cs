using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
	 /// <summary>This exception is thrown whenever we find something we don't expect in a message.</summary>
    [Serializable]
    public class InvalidCipherTextException
		: CryptoException
    {
		public InvalidCipherTextException()
			: base()
		{
		}

		public InvalidCipherTextException(string message)
			: base(message)
		{
		}

		public InvalidCipherTextException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected InvalidCipherTextException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
