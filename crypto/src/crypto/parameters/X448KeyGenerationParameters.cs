using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for X448 (RFC 7748). Carries the <see cref="SecureRandom"/> used for
    /// scalar generation; the strength is fixed at 448 bits.
    /// </summary>
    public class X448KeyGenerationParameters
        : KeyGenerationParameters
    {
        /// <summary>
        /// Construct using <paramref name="random"/> as the entropy source for the 56-byte scalar.
        /// </summary>
        public X448KeyGenerationParameters(SecureRandom random)
            : base(random, 448)
        {
        }
    }
}
