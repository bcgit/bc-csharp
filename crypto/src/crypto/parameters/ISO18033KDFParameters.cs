using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /**
    * parameters for Key derivation functions for ISO-18033
    */
    public class Iso18033KdfParameters
        : IDerivationParameters
    {
        byte[]  seed;

        /// <summary>Create a new <see cref="Iso18033KdfParameters"/>.</summary>
        /// <param name="seed">The seed.</param>
        public Iso18033KdfParameters(
            byte[]  seed)
        {
            this.seed = seed;
        }

        /// <summary>Return the seed.</summary>
        public byte[] GetSeed()
        {
            return seed;
        }
    }
}
