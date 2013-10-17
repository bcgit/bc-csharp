using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public enum EncryptionAlgorithm
    {
        NULL = 0,
        RC4_40 = 1,
        RC4_128 = 2,
        RC2_CBC_40 = 3,
        IDEA_CBC = 4,
        DES40_CBC = 5,
        DES_CBC = 6,
        cls_3DES_EDE_CBC = 7,

        /*
         * RFC 3268
         */
        AES_128_CBC = 8,
        AES_256_CBC = 9,

        /*
         * RFC 5289
         */
        AES_128_GCM = 10,
        AES_256_GCM = 11,   

        /*
         * RFC 4132
         */
        CAMELLIA_128_CBC = 12,
        CAMELLIA_256_CBC = 13,

        /*
         * RFC 4162
         */
        SEED_CBC = 14,

        /*
         * RFC 6655
         */
        AES_128_CCM = 15,
        AES_128_CCM_8 = 16,
        AES_256_CCM = 17,
        AES_256_CCM_8 = 18,

        /*
        * TBD[draft-josefsson-salsa20-tls-02] 
        */
        ESTREAM_SALSA20 = 100,
        SALSA20 = 101,
    }
    
}
