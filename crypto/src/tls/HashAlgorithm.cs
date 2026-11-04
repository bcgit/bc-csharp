using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 5246 7.4.1.4.1</summary>
    public abstract class HashAlgorithm
    {
        /// <summary>The <c>none</c> constant, with the value <c>0</c>.</summary>
        public const short none = 0;
        /// <summary>The <c>md5</c> constant, with the value <c>1</c>.</summary>
        public const short md5 = 1;
        /// <summary>The <c>sha1</c> constant, with the value <c>2</c>.</summary>
        public const short sha1 = 2;
        /// <summary>The <c>sha224</c> constant, with the value <c>3</c>.</summary>
        public const short sha224 = 3;
        /// <summary>The <c>sha256</c> constant, with the value <c>4</c>.</summary>
        public const short sha256 = 4;
        /// <summary>The <c>sha384</c> constant, with the value <c>5</c>.</summary>
        public const short sha384 = 5;
        /// <summary>The <c>sha512</c> constant, with the value <c>6</c>.</summary>
        public const short sha512 = 6;

        /*
         * RFC 8422
         */
        public const short Intrinsic = 8;

        /// <summary>Get the name of the given hash algorithm.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>The name.</returns>
        public static string GetName(short hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
            case none:
                return "none";
            case md5:
                return "md5";
            case sha1:
                return "sha1";
            case sha224:
                return "sha224";
            case sha256:
                return "sha256";
            case sha384:
                return "sha384";
            case sha512:
                return "sha512";
            case Intrinsic:
                return "Intrinsic";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>Get the output size in bytes of a hash algorithm.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>The output size, or -1 if the algorithm has no fixed output size or is not recognized.</returns>
        public static int GetOutputSize(short hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
            case md5:
                return 16;
            case sha1:
                return 20;
            case sha224:
                return 28;
            case sha256:
                return 32;
            case sha384:
                return 48;
            case sha512:
                return 64;
            default:
                return -1;
            }
        }

        /// <summary>
        /// Get a textual representation of the given hash algorithm, made up of its name and its numeric value.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>The text.</returns>
        public static string GetText(short hashAlgorithm)
        {
            return GetName(hashAlgorithm) + "(" + hashAlgorithm + ")";
        }

        /// <summary>Determine whether the given hash algorithm is in the range reserved for private use.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>true if the value is in the private-use range, false otherwise.</returns>
        public static bool IsPrivate(short hashAlgorithm)
        {
            return 224 <= hashAlgorithm && hashAlgorithm <= 255;
        }

        /// <summary>Determine whether the given hash algorithm is a recognized value.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>true if the value is recognized, false otherwise.</returns>
        public static bool IsRecognized(short hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case md5:
                case sha1:
                case sha224:
                case sha256:
                case sha384:
                case sha512:
                case Intrinsic:
                    return true;
                default:
                    return false;
            }
        }
    }
}
