using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 5246</summary>
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values (e.g. serialization).
    /// </remarks>
    public abstract class PrfAlgorithm
    {
        /// <summary>The <c>ssl_prf_legacy</c> constant, with the value <c>0</c>.</summary>
        public const int ssl_prf_legacy = 0;
        /// <summary>The <c>tls_prf_legacy</c> constant, with the value <c>1</c>.</summary>
        public const int tls_prf_legacy = 1;
        /// <summary>The <c>tls_prf_sha256</c> constant, with the value <c>2</c>.</summary>
        public const int tls_prf_sha256 = 2;
        /// <summary>The <c>tls_prf_sha384</c> constant, with the value <c>3</c>.</summary>
        public const int tls_prf_sha384 = 3;
        /// <summary>The <c>tls13_hkdf_sha256</c> constant, with the value <c>4</c>.</summary>
        public const int tls13_hkdf_sha256 = 4;
        /// <summary>The <c>tls13_hkdf_sha384</c> constant, with the value <c>5</c>.</summary>
        public const int tls13_hkdf_sha384 = 5;
        /// <summary>The <c>tls13_hkdf_sm3</c> constant, with the value <c>7</c>.</summary>
        //public const int tls13_hkdf_sha512 = 6;
        public const int tls13_hkdf_sm3 = 7;
        /// <summary>The <c>tls_prf_gostr3411_2012_256</c> constant, with the value <c>8</c>.</summary>
        public const int tls_prf_gostr3411_2012_256 = 8;

        /// <summary>Get the name of the given prf algorithm.</summary>
        /// <param name="prfAlgorithm">The prf algorithm.</param>
        /// <returns>The name.</returns>
        public static string GetName(int prfAlgorithm)
        {
            switch (prfAlgorithm)
            {
            case ssl_prf_legacy:
                return "ssl_prf_legacy";
            case tls_prf_legacy:
                return "tls_prf_legacy";
            case tls_prf_sha256:
                return "tls_prf_sha256";
            case tls_prf_sha384:
                return "tls_prf_sha384";
            case tls13_hkdf_sha256:
                return "tls13_hkdf_sha256";
            case tls13_hkdf_sha384:
                return "tls13_hkdf_sha384";
            case tls13_hkdf_sm3:
                return "tls13_hkdf_sm3";
            case tls_prf_gostr3411_2012_256:
                return "tls_prf_gostr3411_2012_256";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given prf algorithm, made up of its name and its numeric value.
        /// </summary>
        /// <param name="prfAlgorithm">The prf algorithm.</param>
        /// <returns>The text.</returns>
        public static string GetText(int prfAlgorithm)
        {
            return GetName(prfAlgorithm) + "(" + prfAlgorithm + ")";
        }
    }
}
