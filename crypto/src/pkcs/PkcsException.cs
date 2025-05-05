using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Pkcs
{
	/// <summary>Base exception for PKCS related issues.</summary>
	[Serializable]
	public class PkcsException
        : Exception
    {
		public PkcsException()
			: base()
		{
		}

		public PkcsException(string message)
			: base(message)
		{
		}

		public PkcsException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected PkcsException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
