using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 6091</summary>
    public abstract class CertificateType
    {
        public const short X509 = 0;
        public const short OpenPGP = 1;

        /*
         * RFC 7250
         */
        public const short RawPublicKey = 2;

        public static bool IsValid(short certificateType)
        {
            return certificateType >= X509 && certificateType <= RawPublicKey;
        }
    }
}
