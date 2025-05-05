using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>This exception is thrown whenever a cipher requires a change of key, IV or similar after x amount of
	/// bytes enciphered.
	/// </summary>
    [Serializable]
    public class MaxBytesExceededException
		: CryptoException
	{
		public MaxBytesExceededException()
			: base()
		{
		}

		public MaxBytesExceededException(string message)
			: base(message)
		{
		}

		public MaxBytesExceededException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected MaxBytesExceededException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
