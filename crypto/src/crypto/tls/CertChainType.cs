using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    /*
     * RFC 3546 3.3.
     */
    public abstract class CertChainType
    {
        public const short individual_certs = 0;
        public const short pkipath = 1;

        public static bool IsValid(short certChainType)
        {
            return certChainType >= individual_certs && certChainType <= pkipath;
        }
    }
}
