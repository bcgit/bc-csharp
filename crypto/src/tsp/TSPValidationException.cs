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
		private int failureCode;

		public TspValidationException(string message)
			: base(message)
		{
			this.failureCode = -1;
		}

		public TspValidationException(string message, int failureCode)
			: base(message)
		{
			this.failureCode = failureCode;
		}

		protected TspValidationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		/// <returns>The failure code associated with this exception, if one is set.</returns>
		public int FailureCode
		{
			get { return failureCode; }
		}
	}
}
