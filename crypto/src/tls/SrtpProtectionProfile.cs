namespace Org.BouncyCastle.Tls
{
    // TODO[api] Make static
    public abstract class SrtpProtectionProfile
    {
        /*
         * RFC 5764 4.1.2.
         */
        public const int SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001;
        public const int SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002;

        /// <summary>Removed by draft-ietf-avt-dtls-srtp-04.</summary>
        /// <remarks>IANA: Unassigned.</remarks>
        public const int DRAFT_SRTP_AES256_CM_SHA1_80 = 0x0003;
        /// <summary>Removed by draft-ietf-avt-dtls-srtp-04.</summary>
        /// <remarks>IANA: Unassigned.</remarks>
        public const int DRAFT_SRTP_AES256_CM_SHA1_32 = 0x0004;

        public const int SRTP_NULL_HMAC_SHA1_80 = 0x0005;
        public const int SRTP_NULL_HMAC_SHA1_32 = 0x0006;

        /*
         * RFC 7714 14.2.
         */
        public const int SRTP_AEAD_AES_128_GCM = 0x0007;
        public const int SRTP_AEAD_AES_256_GCM = 0x0008;

        /*
         * RFC 8723 10.1.
         */
        public const int DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 0x0009;
        public const int DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = 0x000A;

        /*
         * RFC 8269 6.1.
         */
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_80 = 0x000B;
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_32 = 0x000C;
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_80 = 0x000D;
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_32 = 0x000E;
        public const int SRTP_AEAD_ARIA_128_GCM = 0x000F;
        public const int SRTP_AEAD_ARIA_256_GCM = 0x0010;
    }
}
