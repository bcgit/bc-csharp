namespace Org.BouncyCastle.Security
{
    internal static class SecurityUtilities
    {
        /*
         * These three got introduced in some messages as a result of a typo in an early document. We don't produce
         * anything using these OID values, but we'll read them.
         */
        internal static readonly string WrongAes128 = "2.16.840.1.101.3.4.2";
        internal static readonly string WrongAes192 = "2.16.840.1.101.3.4.22";
        internal static readonly string WrongAes256 = "2.16.840.1.101.3.4.42";
    }
}
