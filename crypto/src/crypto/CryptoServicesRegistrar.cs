using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    public static class CryptoServicesRegistrar
    {
        public static SecureRandom GetSecureRandom()
        {
            return new SecureRandom();
        }

        public static SecureRandom GetSecureRandom(SecureRandom secureRandom)
        {
            return secureRandom ?? new SecureRandom();
        }
    }
}
