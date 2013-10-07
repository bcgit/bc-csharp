namespace Org.BouncyCastle.Crypto.Tls
{

    internal class MaxFragmentLength
    {
        /*
         * RFC 3546 3.2.
         */
        public static short pow2_9 = 1;
        public static short pow2_10 = 2;
        public static short pow2_11 = 3;
        public static short pow2_12 = 4;

        public static bool IsValid(short maxFragmentLength)
        {
            return maxFragmentLength >= pow2_9 && maxFragmentLength <= pow2_12;
        }
    }

}
