using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    public static class CryptoServicesRegistrar
    {
        /// <summary>Return the secure random.</summary>
        public static SecureRandom GetSecureRandom()
        {
            return new SecureRandom();
        }

        public static SecureRandom GetSecureRandom(SecureRandom secureRandom)
        {
            return secureRandom ?? GetSecureRandom();
        }
    }
}
