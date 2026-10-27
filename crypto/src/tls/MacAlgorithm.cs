using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246</summary>
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values (e.g. serialization).
    /// </remarks>
    // TODO[api] Make static
    public abstract class MacAlgorithm
    {
        /// <summary>The <c>cls_null</c> constant, with the value <c>0</c>.</summary>
        public const int cls_null = 0;
        /// <summary>The <c>md5</c> constant, with the value <c>1</c>.</summary>
        public const int md5 = 1;
        /// <summary>The <c>sha</c> constant, with the value <c>2</c>.</summary>
        public const int sha = 2;

        /*
         * RFC 5246
         */
        public const int hmac_md5 = md5;
        /// <summary>The <c>hmac_sha1</c> constant, with the value <c>2</c>.</summary>
        public const int hmac_sha1 = sha;
        /// <summary>The <c>hmac_sha256</c> constant, with the value <c>3</c>.</summary>
        public const int hmac_sha256 = 3;
        /// <summary>The <c>hmac_sha384</c> constant, with the value <c>4</c>.</summary>
        public const int hmac_sha384 = 4;
        /// <summary>The <c>hmac_sha512</c> constant, with the value <c>5</c>.</summary>
        public const int hmac_sha512 = 5;

        /// <summary>Get the name of the given mac algorithm.</summary>
        /// <param name="macAlgorithm">The mac algorithm.</param>
        /// <returns>The name.</returns>
        public static string GetName(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case cls_null:
                return "null";
            case hmac_md5:
                return "hmac_md5";
            case hmac_sha1:
                return "hmac_sha1";
            case hmac_sha256:
                return "hmac_sha256";
            case hmac_sha384:
                return "hmac_sha384";
            case hmac_sha512:
                return "hmac_sha512";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given mac algorithm, made up of its name and its numeric value.
        /// </summary>
        /// <param name="macAlgorithm">The mac algorithm.</param>
        /// <returns>The text.</returns>
        public static string GetText(int macAlgorithm)
        {
            return GetName(macAlgorithm) + "(" + macAlgorithm + ")";
        }

        /// <summary>Determine whether a MAC algorithm is an HMAC.</summary>
        /// <param name="macAlgorithm">The MAC algorithm.</param>
        /// <returns>true if the algorithm is an HMAC, false otherwise.</returns>
        public static bool IsHmac(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case hmac_md5:
            case hmac_sha1:
            case hmac_sha256:
            case hmac_sha384:
            case hmac_sha512:
                return true;
            default:
                return false;
            }
        }
    }
}
