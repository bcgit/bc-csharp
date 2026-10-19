using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>The trailer values used by ISO 9796-2 signatures.</summary>
    public class IsoTrailers
    {
        /// <summary>The <c>TRAILER_IMPLICIT</c> constant, with the value <c>0xBC</c>.</summary>
        public const int TRAILER_IMPLICIT    = 0xBC;
        /// <summary>The <c>TRAILER_RIPEMD160</c> constant, with the value <c>0x31CC</c>.</summary>
        public const int TRAILER_RIPEMD160   = 0x31CC;
        /// <summary>The <c>TRAILER_RIPEMD128</c> constant, with the value <c>0x32CC</c>.</summary>
        public const int TRAILER_RIPEMD128   = 0x32CC;
        /// <summary>The <c>TRAILER_SHA1</c> constant, with the value <c>0x33CC</c>.</summary>
        public const int TRAILER_SHA1        = 0x33CC;
        /// <summary>The <c>TRAILER_SHA256</c> constant, with the value <c>0x34CC</c>.</summary>
        public const int TRAILER_SHA256      = 0x34CC;
        /// <summary>The <c>TRAILER_SHA512</c> constant, with the value <c>0x35CC</c>.</summary>
        public const int TRAILER_SHA512      = 0x35CC;
        /// <summary>The <c>TRAILER_SHA384</c> constant, with the value <c>0x36CC</c>.</summary>
        public const int TRAILER_SHA384      = 0x36CC;
        /// <summary>The <c>TRAILER_WHIRLPOOL</c> constant, with the value <c>0x37CC</c>.</summary>
        public const int TRAILER_WHIRLPOOL   = 0x37CC;
        /// <summary>The <c>TRAILER_SHA224</c> constant, with the value <c>0x38CC</c>.</summary>
        public const int TRAILER_SHA224      = 0x38CC;
        /// <summary>The <c>TRAILER_SHA512_224</c> constant, with the value <c>0x39CC</c>.</summary>
        public const int TRAILER_SHA512_224  = 0x39CC;
        /// <summary>The <c>TRAILER_SHA512_256</c> constant, with the value <c>0x40CC</c>.</summary>
        public const int TRAILER_SHA512_256  = 0x40CC;

        private static IDictionary<string, int> CreateTrailerMap()
        {
            var trailers = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            trailers.Add("RIPEMD128", TRAILER_RIPEMD128);
            trailers.Add("RIPEMD160", TRAILER_RIPEMD160);

            trailers.Add("SHA-1", TRAILER_SHA1);
            trailers.Add("SHA-224", TRAILER_SHA224);
            trailers.Add("SHA-256", TRAILER_SHA256);
            trailers.Add("SHA-384", TRAILER_SHA384);
            trailers.Add("SHA-512", TRAILER_SHA512);
            trailers.Add("SHA-512/224", TRAILER_SHA512_224);
            trailers.Add("SHA-512/256", TRAILER_SHA512_256);

            trailers.Add("Whirlpool", TRAILER_WHIRLPOOL);

            return trailers;
        }

        // IDictionary is (string -> Int32)
        private static readonly IDictionary<string, int> TrailerMap = CreateTrailerMap();

        public static int GetTrailer(IDigest digest)
        {
            if (TrailerMap.TryGetValue(digest.AlgorithmName, out var trailer))
                return trailer;

            throw new InvalidOperationException("No trailer for digest");
        }

        public static bool NoTrailerAvailable(IDigest digest)
        {
            return !TrailerMap.ContainsKey(digest.AlgorithmName);
        }
    }
}
