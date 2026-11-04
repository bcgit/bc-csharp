using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for RC5, holding the key and the number of rounds.</summary>
    public class RC5Parameters
        : KeyParameter
    {
        private readonly int rounds;

        /// <summary>Create a new <see cref="RC5Parameters"/>.</summary>
        /// <param name="key">The key.</param>
        /// <param name="rounds">The rounds.</param>
        public RC5Parameters(
            byte[] key,
            int rounds)
            : base(key)
        {
            if (key.Length > 255)
                throw new ArgumentException("RC5 key length can be no greater than 255");

            this.rounds = rounds;
        }

        /// <summary>Gets the rounds.</summary>
        public int Rounds
        {
            get { return rounds; }
        }
    }
}
