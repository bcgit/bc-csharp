using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for Ed448 (RFC 8032). Carries the <see cref="SecureRandom"/> used for
    /// seed generation; the strength is fixed at 448 bits.
    /// </summary>
    public class Ed448KeyGenerationParameters
        : KeyGenerationParameters
    {
        /// <summary>
        /// Construct using <paramref name="random"/> as the entropy source for the 57-byte seed.
        /// </summary>
        public Ed448KeyGenerationParameters(SecureRandom random)
            : base(random, 448)
        {
        }
    }
}
