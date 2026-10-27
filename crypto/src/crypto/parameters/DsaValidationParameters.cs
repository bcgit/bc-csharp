using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>The seed and counter used to generate DSA domain parameters, so that they can be validated.</summary>
    public class DsaValidationParameters
    {
        private readonly byte[] seed;
        private readonly int counter;
        private readonly int usageIndex;

        /// <summary>Create a new <see cref="DsaValidationParameters"/>.</summary>
        /// <param name="seed">The seed.</param>
        /// <param name="counter">The counter.</param>
        public DsaValidationParameters(byte[] seed, int counter)
            : this(seed, counter, -1)
        {
        }

        /// <summary>Create a new <see cref="DsaValidationParameters"/>.</summary>
        /// <param name="seed">The seed.</param>
        /// <param name="counter">The counter.</param>
        /// <param name="usageIndex">The usage index.</param>
        public DsaValidationParameters(
            byte[] seed,
            int counter,
            int     usageIndex)
        {
            if (seed == null)
                throw new ArgumentNullException("seed");

            this.seed = (byte[]) seed.Clone();
            this.counter = counter;
            this.usageIndex = usageIndex;
        }

        /// <summary>Return the seed.</summary>
        public virtual byte[] GetSeed()
        {
            return (byte[]) seed.Clone();
        }

        /// <summary>Gets the counter.</summary>
        public virtual int Counter
        {
            get { return counter; }
        }

        /// <summary>Gets the usage index.</summary>
        public virtual int UsageIndex
        {
            get { return usageIndex; }
        }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            DsaValidationParameters other = obj as DsaValidationParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected virtual bool Equals(
            DsaValidationParameters other)
        {
            return counter == other.counter
                && Arrays.AreEqual(seed, other.seed);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return counter.GetHashCode() ^ Arrays.GetHashCode(seed);
        }
    }
}
