using System;
using System.IO;

namespace Org.BouncyCastle.Security
{
#if !PORTABLE
    [Serializable]
#endif
    public class PasswordException
		: IOException
	{
		public PasswordException(
			string message)
			: base(message)
		{
		}

		public PasswordException(
			string		message,
			Exception	exception)
			: base(message, exception)
		{
		}
	}
}
