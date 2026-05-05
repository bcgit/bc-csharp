using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for X25519 (RFC 7748). Carries the <see cref="SecureRandom"/> used for
    /// scalar generation; the strength is fixed at 255 bits.
    /// </summary>
    public class X25519KeyGenerationParameters
        : KeyGenerationParameters
    {
        /// <summary>
        /// Construct using <paramref name="random"/> as the entropy source for the 32-byte scalar.
        /// </summary>
        public X25519KeyGenerationParameters(SecureRandom random)
            : base(random, 255)
        {
        }
    }
}
