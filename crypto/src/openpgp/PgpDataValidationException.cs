using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <summary>Thrown if the IV at the start of a data stream indicates the wrong key is being used.</summary>
    [Serializable]
    public class PgpDataValidationException
        : PgpException
	{
		public PgpDataValidationException()
			: base()
		{
		}

		public PgpDataValidationException(string message)
			: base(message)
		{
		}

		public PgpDataValidationException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected PgpDataValidationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
