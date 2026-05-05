using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for Ed25519 (RFC 8032). Carries the <see cref="SecureRandom"/> used for
    /// seed generation; the strength is fixed at 256 bits.
    /// </summary>
    public class Ed25519KeyGenerationParameters
        : KeyGenerationParameters
    {
        /// <summary>
        /// Construct using <paramref name="random"/> as the entropy source for the 32-byte seed.
        /// </summary>
        public Ed25519KeyGenerationParameters(SecureRandom random)
            : base(random, 256)
        {
        }
    }
}
