using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>This exception is thrown if a buffer that is meant to have output copied into it turns out to be too
	/// short, or if we've been given insufficient input.</summary>
	/// <remarks>
	/// In general this exception will get thrown rather than an <see cref="IndexOutOfRangeException"/>.
	/// </remarks>
	[Serializable]
    public class DataLengthException
		: CryptoException
	{
		public DataLengthException()
			: base()
		{
		}

		public DataLengthException(string message)
			: base(message)
		{
		}

		public DataLengthException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected DataLengthException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
