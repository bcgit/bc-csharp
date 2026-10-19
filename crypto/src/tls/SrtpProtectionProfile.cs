namespace Org.BouncyCastle.Tls
{
    // TODO[api] Make static
    public abstract class SrtpProtectionProfile
    {
        /*
         * RFC 5764 4.1.2.
         */
        public const int SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001;
        /// <summary>The <c>SRTP_AES128_CM_HMAC_SHA1_32</c> constant, with the value <c>0x0002</c>.</summary>
        public const int SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002;

        /// <summary>Removed by draft-ietf-avt-dtls-srtp-04.</summary>
        /// <remarks>IANA: Unassigned.</remarks>
        public const int DRAFT_SRTP_AES256_CM_SHA1_80 = 0x0003;
        /// <summary>Removed by draft-ietf-avt-dtls-srtp-04.</summary>
        /// <remarks>IANA: Unassigned.</remarks>
        public const int DRAFT_SRTP_AES256_CM_SHA1_32 = 0x0004;

        /// <summary>The <c>SRTP_NULL_HMAC_SHA1_80</c> constant, with the value <c>0x0005</c>.</summary>
        public const int SRTP_NULL_HMAC_SHA1_80 = 0x0005;
        /// <summary>The <c>SRTP_NULL_HMAC_SHA1_32</c> constant, with the value <c>0x0006</c>.</summary>
        public const int SRTP_NULL_HMAC_SHA1_32 = 0x0006;

        /*
         * RFC 7714 14.2.
         */
        public const int SRTP_AEAD_AES_128_GCM = 0x0007;
        /// <summary>The <c>SRTP_AEAD_AES_256_GCM</c> constant, with the value <c>0x0008</c>.</summary>
        public const int SRTP_AEAD_AES_256_GCM = 0x0008;

        /*
         * RFC 8723 10.1.
         */
        public const int DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 0x0009;
        /// <summary>
        /// The <c>DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM</c> constant, with the value <c>0x000A</c>.
        /// </summary>
        public const int DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = 0x000A;

        /*
         * RFC 8269 6.1.
         */
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_80 = 0x000B;
        /// <summary>The <c>SRTP_ARIA_128_CTR_HMAC_SHA1_32</c> constant, with the value <c>0x000C</c>.</summary>
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_32 = 0x000C;
        /// <summary>The <c>SRTP_ARIA_256_CTR_HMAC_SHA1_80</c> constant, with the value <c>0x000D</c>.</summary>
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_80 = 0x000D;
        /// <summary>The <c>SRTP_ARIA_256_CTR_HMAC_SHA1_32</c> constant, with the value <c>0x000E</c>.</summary>
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_32 = 0x000E;
        /// <summary>The <c>SRTP_AEAD_ARIA_128_GCM</c> constant, with the value <c>0x000F</c>.</summary>
        public const int SRTP_AEAD_ARIA_128_GCM = 0x000F;
        /// <summary>The <c>SRTP_AEAD_ARIA_256_GCM</c> constant, with the value <c>0x0010</c>.</summary>
        public const int SRTP_AEAD_ARIA_256_GCM = 0x0010;
    }
}
