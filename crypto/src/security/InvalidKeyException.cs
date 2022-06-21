using System;

namespace Org.BouncyCastle.Security
{
#if !PORTABLE
    [Serializable]
#endif
    public class InvalidKeyException : KeyException
	{
		public InvalidKeyException() : base() { }
		public InvalidKeyException(string message) : base(message) { }
		public InvalidKeyException(string message, Exception exception) : base(message, exception) { }
	}
}
