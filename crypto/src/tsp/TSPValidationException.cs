using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Tsp
{
	/**
	 * Exception thrown if a TSP request or response fails to validate.
	 * <p>
	 * If a failure code is associated with the exception it can be retrieved using
	 * the getFailureCode() method.</p>
	 */
    [Serializable]
    public class TspValidationException
		: TspException
	{
		protected readonly int m_failureCode;

		public TspValidationException(string message)
			: this(message, -1)
		{
		}

		public TspValidationException(string message, int failureCode)
			: base(message)
		{
			m_failureCode = failureCode;
		}

#if NET8_0_OR_GREATER
		[System.Obsolete( 
			"This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", 
			DiagnosticId = "SYSLIB0051", UrlFormat = "https://aka.ms/dotnet-warnings/{0}" 
		)]
#endif
		protected TspValidationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
			m_failureCode = info.GetInt32("failureCode");
		}

#if NET8_0_OR_GREATER
		[Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.", DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
			info.AddValue("failureCode", m_failureCode);
		}

		/// <returns>The failure code associated with this exception, if one is set.</returns>
		public int FailureCode
		{
			get { return m_failureCode; }
		}
	}
}
