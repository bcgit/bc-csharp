using System;
using System.IO;

namespace Org.BouncyCastle.Security
{
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || UNITY_WINRT)
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
