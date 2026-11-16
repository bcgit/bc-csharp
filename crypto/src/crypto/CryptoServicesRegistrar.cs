using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Provides access to services shared by the cryptographic classes, such as a default source of randomness.
    /// </summary>
    public static class CryptoServicesRegistrar
    {
        /// <summary>Return the secure random.</summary>
        public static SecureRandom GetSecureRandom()
        {
            return new SecureRandom();
        }

        /// <summary>Return a source of randomness, using the one supplied if there is one.</summary>
        /// <param name="secureRandom">The source of randomness to use, or null.</param>
        /// <returns><paramref name="secureRandom"/> if it is not null, otherwise a new default source.</returns>
        public static SecureRandom GetSecureRandom(SecureRandom secureRandom)
        {
            return secureRandom ?? GetSecureRandom();
        }
    }
}
