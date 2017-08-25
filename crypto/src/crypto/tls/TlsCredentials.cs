using System;

namespace Org.BouncyCastle.Crypto.Tls
{
	public interface TlsCredentials
	{
		AbstractCertificate Certificate { get; }
	}
}
