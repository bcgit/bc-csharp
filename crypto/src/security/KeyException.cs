using System;

namespace Org.BouncyCastle.Security
{
#if !PORTABLE
    [Serializable]
#endif
    public class KeyException : GeneralSecurityException
	{
		public KeyException() : base() { }
		public KeyException(string message) : base(message) { }
		public KeyException(string message, Exception exception) : base(message, exception) { }
	}
}
