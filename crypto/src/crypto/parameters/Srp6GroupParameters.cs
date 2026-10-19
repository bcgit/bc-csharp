using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>The group parameters (N and g) used by the SRP-6 protocol.</summary>
    public sealed class Srp6GroupParameters
    {
        private readonly BigInteger n, g;

        /// <summary>Create a new <see cref="Srp6GroupParameters"/>.</summary>
        /// <param name="N">The n.</param>
        /// <param name="g">The g.</param>
        public Srp6GroupParameters(BigInteger N, BigInteger g)
        {
            this.n = N;
            this.g = g;
        }

        /// <summary>Gets the g.</summary>
        public BigInteger G
        {
            get { return g; }
        }

        /// <summary>Gets the n.</summary>
        public BigInteger N
        {
            get { return n; }
        }
    }
}
