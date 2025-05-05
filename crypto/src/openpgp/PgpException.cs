using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <summary>Generic exception class for PGP encoding/decoding problems.</summary>
    [Serializable]
    public class PgpException
		: Exception
	{
		public PgpException()
			: base()
		{
		}

		public PgpException(string message)
			: base(message)
		{
		}

		public PgpException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected PgpException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
