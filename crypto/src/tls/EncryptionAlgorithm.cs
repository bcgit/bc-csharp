using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246</summary>
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values (e.g. serialization).
    /// </remarks>
    // TODO[api] Make static
    public abstract class EncryptionAlgorithm
    {
        /// <summary>The <c>NULL</c> constant, with the value <c>0</c>.</summary>
        public const int NULL = 0;
        /// <summary>The <c>RC4_40</c> constant, with the value <c>1</c>.</summary>
        public const int RC4_40 = 1;
        /// <summary>The <c>RC4_128</c> constant, with the value <c>2</c>.</summary>
        public const int RC4_128 = 2;
        /// <summary>The <c>RC2_CBC_40</c> constant, with the value <c>3</c>.</summary>
        public const int RC2_CBC_40 = 3;
        /// <summary>The <c>IDEA_CBC</c> constant, with the value <c>4</c>.</summary>
        public const int IDEA_CBC = 4;
        /// <summary>The <c>DES40_CBC</c> constant, with the value <c>5</c>.</summary>
        public const int DES40_CBC = 5;
        /// <summary>The <c>DES_CBC</c> constant, with the value <c>6</c>.</summary>
        public const int DES_CBC = 6;
        /// <summary>The <c>cls_3DES_EDE_CBC</c> constant, with the value <c>7</c>.</summary>
        public const int cls_3DES_EDE_CBC = 7;

        /*
         * RFC 3268
         */
        public const int AES_128_CBC = 8;
        /// <summary>The <c>AES_256_CBC</c> constant, with the value <c>9</c>.</summary>
        public const int AES_256_CBC = 9;

        /*
         * RFC 5289
         */
        public const int AES_128_GCM = 10;
        /// <summary>The <c>AES_256_GCM</c> constant, with the value <c>11</c>.</summary>
        public const int AES_256_GCM = 11;

        /*
         * RFC 5932
         */
        public const int CAMELLIA_128_CBC = 12;
        /// <summary>The <c>CAMELLIA_256_CBC</c> constant, with the value <c>13</c>.</summary>
        public const int CAMELLIA_256_CBC = 13;

        /*
         * RFC 4162
         */
        public const int SEED_CBC = 14;

        /*
         * RFC 6655
         */
        public const int AES_128_CCM = 15;
        /// <summary>The <c>AES_128_CCM_8</c> constant, with the value <c>16</c>.</summary>
        public const int AES_128_CCM_8 = 16;
        /// <summary>The <c>AES_256_CCM</c> constant, with the value <c>17</c>.</summary>
        public const int AES_256_CCM = 17;
        /// <summary>The <c>AES_256_CCM_8</c> constant, with the value <c>18</c>.</summary>
        public const int AES_256_CCM_8 = 18;

        /*
         * RFC 6367
         */
        public const int CAMELLIA_128_GCM = 19;
        /// <summary>The <c>CAMELLIA_256_GCM</c> constant, with the value <c>20</c>.</summary>
        public const int CAMELLIA_256_GCM = 20;

        /*
         * RFC 7905
         */
        public const int CHACHA20_POLY1305 = 21;

        /*
         * RFC 6209
         */
        public const int ARIA_128_CBC = 22;
        /// <summary>The <c>ARIA_256_CBC</c> constant, with the value <c>23</c>.</summary>
        public const int ARIA_256_CBC = 23;
        /// <summary>The <c>ARIA_128_GCM</c> constant, with the value <c>24</c>.</summary>
        public const int ARIA_128_GCM = 24;
        /// <summary>The <c>ARIA_256_GCM</c> constant, with the value <c>25</c>.</summary>
        public const int ARIA_256_GCM = 25;

        /*
         * RFC 8998
         */
        public const int SM4_CCM = 26;
        /// <summary>The <c>SM4_GCM</c> constant, with the value <c>27</c>.</summary>
        public const int SM4_GCM = 27;

        /*
         * GMT 0024-2014
         */
        public const int SM4_CBC = 28;

        /*
         * RFC 9189
         */
        public const int KUZNYECHIK_CTR_OMAC = 29;
        /// <summary>The <c>MAGMA_CTR_OMAC</c> constant, with the value <c>30</c>.</summary>
        public const int MAGMA_CTR_OMAC = 30;
        /// <summary>The <c>cls_28147_CNT_IMIT</c> constant, with the value <c>31</c>.</summary>
        public const int cls_28147_CNT_IMIT = 31;

        /*
         * RFC 9150
         */
        public const int NULL_HMAC_SHA256 = 32;
        /// <summary>The <c>NULL_HMAC_SHA384</c> constant, with the value <c>33</c>.</summary>
        public const int NULL_HMAC_SHA384 = 33;
    }
}
