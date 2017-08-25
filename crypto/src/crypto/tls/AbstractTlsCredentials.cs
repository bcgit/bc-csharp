using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class AbstractTlsCredentials
        :   TlsCredentials
    {
        public abstract AbstractCertificate Certificate { get; }
    }
}
