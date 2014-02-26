using System;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
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
