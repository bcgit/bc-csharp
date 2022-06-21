using System;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
#if !PORTABLE
    [Serializable]
#endif
    public class PemException
		: IOException
	{
		public PemException(
			string message)
			: base(message)
		{
		}

		public PemException(
			string		message,
			Exception	exception)
			: base(message, exception)
		{
		}
	}
}
