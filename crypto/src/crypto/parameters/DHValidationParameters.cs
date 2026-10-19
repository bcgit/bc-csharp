using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// The seed and counter used to generate Diffie-Hellman domain parameters, so that they can be validated.
    /// </summary>
    public class DHValidationParameters
    {
        private readonly byte[] m_seed;
        private readonly int m_counter;

        /// <summary>Create a new <see cref="DHValidationParameters"/>.</summary>
        /// <param name="seed">The seed.</param>
        /// <param name="counter">The counter.</param>
        public DHValidationParameters(byte[] seed, int counter)
        {
            m_seed = Arrays.Clone(seed ?? throw new ArgumentNullException(nameof(seed)));
            m_counter = counter;
        }

        /// <summary>Return the seed.</summary>
        public byte[] GetSeed() => Arrays.Clone(m_seed);

        /// <summary>Gets the counter.</summary>
        public int Counter => m_counter;

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is DHValidationParameters that
                && Equals(that);
        }

        protected bool Equals(DHValidationParameters other) =>
            m_counter == other.m_counter && Arrays.AreEqual(this.m_seed, other.m_seed);

        /// <inheritdoc/>
        public override int GetHashCode() => m_counter.GetHashCode() ^ Arrays.GetHashCode(m_seed);
    }
}
