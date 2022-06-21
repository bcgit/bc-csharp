using System;

namespace Org.BouncyCastle.Security.Certificates
{
#if !PORTABLE
    [Serializable]
#endif
    public class CertificateParsingException : CertificateException
	{
		public CertificateParsingException() : base() { }
		public CertificateParsingException(string message) : base(message) { }
		public CertificateParsingException(string message, Exception exception) : base(message, exception) { }
	}
}
