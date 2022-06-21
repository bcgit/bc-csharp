using System;

namespace Org.BouncyCastle.Ocsp
{
#if !PORTABLE
    [Serializable]
#endif
    public class OcspException
		: Exception
	{
		public OcspException()
		{
		}

		public OcspException(
			string message)
			: base(message)
		{
		}

		public OcspException(
			string		message,
			Exception	e)
			: base(message, e)
		{
		}
	}
}
