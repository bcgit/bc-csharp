using System;

namespace Org.BouncyCastle.Tls
{
    /**
     * RFC 5246 7.4.1.4.1 (in RFC 2246, there were no specific values assigned)
     */
    public class SignatureAlgorithm
    {
        /// <summary>The <c>anonymous</c> constant, with the value <c>0</c>.</summary>
        public const short anonymous = 0;
        /// <summary>The <c>rsa</c> constant, with the value <c>1</c>.</summary>
        public const short rsa = 1;
        /// <summary>The <c>dsa</c> constant, with the value <c>2</c>.</summary>
        public const short dsa = 2;
        /// <summary>The <c>ecdsa</c> constant, with the value <c>3</c>.</summary>
        public const short ecdsa = 3;

        /*
         * RFC 8422
         */
        public const short ed25519 = 7;
        /// <summary>The <c>ed448</c> constant, with the value <c>8</c>.</summary>
        public const short ed448 = 8;

        /*
         * RFC 8446 (implied from SignatureScheme values)
         * RFC 8447 reserved these values without allocating the implied names
         */
        public const short rsa_pss_rsae_sha256 = 4;
        /// <summary>The <c>rsa_pss_rsae_sha384</c> constant, with the value <c>5</c>.</summary>
        public const short rsa_pss_rsae_sha384 = 5;
        /// <summary>The <c>rsa_pss_rsae_sha512</c> constant, with the value <c>6</c>.</summary>
        public const short rsa_pss_rsae_sha512 = 6;
        /// <summary>The <c>rsa_pss_pss_sha256</c> constant, with the value <c>9</c>.</summary>
        public const short rsa_pss_pss_sha256 = 9;
        /// <summary>The <c>rsa_pss_pss_sha384</c> constant, with the value <c>10</c>.</summary>
        public const short rsa_pss_pss_sha384 = 10;
        /// <summary>The <c>rsa_pss_pss_sha512</c> constant, with the value <c>11</c>.</summary>
        public const short rsa_pss_pss_sha512 = 11;

        /*
         * RFC 8734 (implied from SignatureScheme values)
         */
        public const short ecdsa_brainpoolP256r1tls13_sha256 = 26;
        /// <summary>The <c>ecdsa_brainpoolP384r1tls13_sha384</c> constant, with the value <c>27</c>.</summary>
        public const short ecdsa_brainpoolP384r1tls13_sha384 = 27;
        /// <summary>The <c>ecdsa_brainpoolP512r1tls13_sha512</c> constant, with the value <c>28</c>.</summary>
        public const short ecdsa_brainpoolP512r1tls13_sha512 = 28;

        /*
         * RFC 9189
         */
        public const short gostr34102012_256 = 64;
        /// <summary>The <c>gostr34102012_512</c> constant, with the value <c>65</c>.</summary>
        public const short gostr34102012_512 = 65;

        public static short GetClientCertificateType(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return ClientCertificateType.rsa_sign;

            case SignatureAlgorithm.dsa:
                return ClientCertificateType.dss_sign;

            case SignatureAlgorithm.ecdsa:
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
                return ClientCertificateType.ecdsa_sign;

            case SignatureAlgorithm.gostr34102012_256:
                return ClientCertificateType.gost_sign256;

            case SignatureAlgorithm.gostr34102012_512:
                return ClientCertificateType.gost_sign512;

            default:
                return -1;
            }
        }

        /// <summary>Get the name of the given signature algorithm.</summary>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <returns>The name.</returns>
        public static string GetName(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case anonymous:
                return "anonymous";
            case rsa:
                return "rsa";
            case dsa:
                return "dsa";
            case ecdsa:
                return "ecdsa";
            case rsa_pss_rsae_sha256:
                return "rsa_pss_rsae_sha256";
            case rsa_pss_rsae_sha384:
                return "rsa_pss_rsae_sha384";
            case rsa_pss_rsae_sha512:
                return "rsa_pss_rsae_sha512";
            case ed25519:
                return "ed25519";
            case ed448:
                return "ed448";
            case rsa_pss_pss_sha256:
                return "rsa_pss_pss_sha256";
            case rsa_pss_pss_sha384:
                return "rsa_pss_pss_sha384";
            case rsa_pss_pss_sha512:
                return "rsa_pss_pss_sha512";
            case ecdsa_brainpoolP256r1tls13_sha256:
                return "ecdsa_brainpoolP256r1tls13_sha256";
            case ecdsa_brainpoolP384r1tls13_sha384:
                return "ecdsa_brainpoolP384r1tls13_sha384";
            case ecdsa_brainpoolP512r1tls13_sha512:
                return "ecdsa_brainpoolP512r1tls13_sha512";
            case gostr34102012_256:
                return "gostr34102012_256";
            case gostr34102012_512:
                return "gostr34102012_512";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given signature algorithm, made up of its name and its numeric value.
        /// </summary>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <returns>The text.</returns>
        public static string GetText(short signatureAlgorithm)
        {
            return GetName(signatureAlgorithm) + "(" + signatureAlgorithm + ")";
        }

        /// <summary>Determine whether the given signature algorithm is a recognized value.</summary>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <returns>true if the value is recognized, false otherwise.</returns>
        public static bool IsRecognized(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case anonymous:
            case rsa:
            case dsa:
            case ecdsa:
            case rsa_pss_rsae_sha256:
            case rsa_pss_rsae_sha384:
            case rsa_pss_rsae_sha512:
            case ed25519:
            case ed448:
            case rsa_pss_pss_sha256:
            case rsa_pss_pss_sha384:
            case rsa_pss_pss_sha512:
            case ecdsa_brainpoolP256r1tls13_sha256:
            case ecdsa_brainpoolP384r1tls13_sha384:
            case ecdsa_brainpoolP512r1tls13_sha512:
            case gostr34102012_256:
            case gostr34102012_512:
                return true;
            default:
                return false;
            }
        }
    }
}
