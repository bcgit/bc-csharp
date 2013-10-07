using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public enum KeyExchangeAlgorithm
    {
        /*
         * Note that the values here are implementation-specific and arbitrary.
         * It is recommended not to depend on the particular values (e.g. serialization).
         */
        NULL = 0,
        RSA = 1,
        RSA_EXPORT = 2,
        DHE_DSS = 3,
        DHE_DSS_EXPORT = 4,
        DHE_RSA = 5,
        DHE_RSA_EXPORT = 6,
        DH_DSS = 7,
        DH_DSS_EXPORT = 8,
        DH_RSA = 9,
        DH_RSA_EXPORT = 10,
        DH_anon = 11,
        DH_anon_EXPORT = 12,

        /*
         * RFC 4279
         */
        PSK = 13,
        DHE_PSK = 14,
        RSA_PSK = 15,

        /*
         * RFC 4429
         */
        ECDH_ECDSA = 16,
        ECDHE_ECDSA = 17,
        ECDH_RSA = 18,
        ECDHE_RSA = 19,
        ECDH_anon = 20,

        /*
         * RFC 5054
         */
        SRP = 21,
        SRP_DSS = 22,
        SRP_RSA = 23,

        /*
         * RFC 5489
         */
        ECDHE_PSK = 24,
    }
}
