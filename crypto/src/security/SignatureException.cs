using System;

namespace Org.BouncyCastle.Security
{
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || UNITY_WINRT)
    [Serializable]
#endif
    public class SignatureException : GeneralSecurityException
	{
		public SignatureException() : base() { }
		public SignatureException(string message) : base(message) { }
		public SignatureException(string message, Exception exception) : base(message, exception) { }
	}
}
