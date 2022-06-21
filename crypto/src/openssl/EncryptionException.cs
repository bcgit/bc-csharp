using System;
using System.IO;

namespace Org.BouncyCastle.Security
{
#if !PORTABLE
    [Serializable]
#endif
    public class EncryptionException
		: IOException
	{
		public EncryptionException(
			string message)
			: base(message)
		{
		}

		public EncryptionException(
			string		message,
			Exception	exception)
			: base(message, exception)
		{
		}
	}
}
