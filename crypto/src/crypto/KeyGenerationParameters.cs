using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /**
     * The base class for parameters to key generators.
     */
    public class KeyGenerationParameters
    {
        private readonly SecureRandom m_random;
        private readonly int m_strength;

        /**
         * initialise the generator with a source of randomness
         * and a strength (in bits).
         *
         * @param random the random byte source.
         * @param strength the size, in bits, of the keys we want to produce.
         */
        public KeyGenerationParameters(SecureRandom random, int strength)
        {
            if (strength < 0)
                throw new ArgumentException("cannot be negative", nameof(strength));

            m_random = random ?? throw new ArgumentNullException(nameof(random));
            m_strength = strength;
        }

        /**
         * return the random source associated with this
         * generator.
         *
         * @return the generators random source.
         */
        public SecureRandom Random => m_random;

        /**
         * return the bit strength for keys produced by this generator,
         *
         * @return the strength of the keys this generator produces (in bits).
         */
        public int Strength => m_strength;
    }
}
