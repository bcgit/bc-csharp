using System;

namespace Org.BouncyCastle.Tls
{
    /**
     * RFC 8879
     */
    public abstract class CertificateCompressionAlgorithm
    {
        /// <summary>The <c>zlib</c> constant, with the value <c>1</c>.</summary>
        public const int zlib = 1;
        /// <summary>The <c>brotli</c> constant, with the value <c>2</c>.</summary>
        public const int brotli = 2;
        /// <summary>The <c>zstd</c> constant, with the value <c>3</c>.</summary>
        public const int zstd = 3;

        /// <summary>Get the name of the given certificate compression algorithm.</summary>
        /// <param name="certificateCompressionAlgorithm">The certificate compression algorithm.</param>
        /// <returns>The name.</returns>
        public static string GetName(int certificateCompressionAlgorithm)
        {
            switch (certificateCompressionAlgorithm)
            {
            case zlib:
                return "zlib";
            case brotli:
                return "brotli";
            case zstd:
                return "zstd";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given certificate compression algorithm, made up of its name and its
        /// numeric value.
        /// </summary>
        /// <param name="certificateCompressionAlgorithm">The certificate compression algorithm.</param>
        /// <returns>The text.</returns>
        public static string GetText(int certificateCompressionAlgorithm)
        {
            return GetName(certificateCompressionAlgorithm) + "(" + certificateCompressionAlgorithm + ")";
        }

        /// <summary>Determine whether the given certificate compression algorithm is a recognized value.</summary>
        /// <param name="certificateCompressionAlgorithm">The certificate compression algorithm.</param>
        /// <returns>true if the value is recognized, false otherwise.</returns>
        public static bool IsRecognized(int certificateCompressionAlgorithm)
        {
            switch (certificateCompressionAlgorithm)
            {
            case zlib:
            case brotli:
            case zstd:
                return true;
            default:
                return false;
            }
        }
    }
}
