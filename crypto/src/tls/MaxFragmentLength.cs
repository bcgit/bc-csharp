using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Constants for the values of the max_fragment_length extension of RFC 6066.</summary>
    public abstract class MaxFragmentLength
    {
        /*
         * RFC 3546 3.2.
         */
        public const short pow2_9 = 1;
        /// <summary>The <c>pow2_10</c> constant, with the value <c>2</c>.</summary>
        public const short pow2_10 = 2;
        /// <summary>The <c>pow2_11</c> constant, with the value <c>3</c>.</summary>
        public const short pow2_11 = 3;
        /// <summary>The <c>pow2_12</c> constant, with the value <c>4</c>.</summary>
        public const short pow2_12 = 4;

        public static bool IsValid(short maxFragmentLength)
        {
            return maxFragmentLength >= pow2_9 && maxFragmentLength <= pow2_12;
        }
    }
}
