using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Security
{
    [Serializable]
    public class SecurityUtilityException
		: Exception
    {
		public SecurityUtilityException()
			: base()
		{
		}

		public SecurityUtilityException(string message)
			: base(message)
		{
		}

		public SecurityUtilityException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected SecurityUtilityException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
