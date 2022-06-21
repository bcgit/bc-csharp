using System;

namespace Org.BouncyCastle.Security
{
#if !PORTABLE
    [Serializable]
#endif
    public class SignatureException : GeneralSecurityException
	{
		public SignatureException() : base() { }
		public SignatureException(string message) : base(message) { }
		public SignatureException(string message, Exception exception) : base(message, exception) { }
	}
}
