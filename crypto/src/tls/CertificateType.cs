using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 6091</summary>
    public abstract class CertificateType
    {
        /// <summary>The <c>X509</c> constant, with the value <c>0</c>.</summary>
        public const short X509 = 0;
        /// <summary>The <c>OpenPGP</c> constant, with the value <c>1</c>.</summary>
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
