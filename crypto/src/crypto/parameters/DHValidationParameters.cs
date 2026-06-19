using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DHValidationParameters
    {
        private readonly byte[] m_seed;
        private readonly int m_counter;

        public DHValidationParameters(byte[] seed, int counter)
        {
            m_seed = Arrays.Clone(seed ?? throw new ArgumentNullException(nameof(seed)));
            m_counter = counter;
        }

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        public int Counter => m_counter;

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is DHValidationParameters that
                && Equals(that);
        }

        protected bool Equals(DHValidationParameters other) =>
            m_counter == other.m_counter && Arrays.AreEqual(this.m_seed, other.m_seed);

        public override int GetHashCode() => m_counter.GetHashCode() ^ Arrays.GetHashCode(m_seed);
    }
}
