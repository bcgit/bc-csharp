using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>ElGamal domain parameters.</summary>
    // TODO[api] Don't implement ICipherParameters
    public class ElGamalParameters
        : ICipherParameters
    {
        private readonly BigInteger p, g;
        private readonly int l;

        /// <summary>Create a new <see cref="ElGamalParameters"/>.</summary>
        /// <param name="p">The prime modulus.</param>
        /// <param name="g">The generator.</param>
        public ElGamalParameters(
            BigInteger p,
            BigInteger g)
            : this(p, g, 0)
        {
        }

        /// <summary>Create a new <see cref="ElGamalParameters"/>.</summary>
        /// <param name="p">The prime modulus.</param>
        /// <param name="g">The generator.</param>
        /// <param name="l">The l.</param>
        public ElGamalParameters(
            BigInteger p,
            BigInteger g,
            int l)
        {
            if (p == null)
                throw new ArgumentNullException("p");
            if (g == null)
                throw new ArgumentNullException("g");

            this.p = p;
            this.g = g;
            this.l = l;
        }

        /// <summary>Gets the p.</summary>
        public BigInteger P
        {
            get { return p; }
        }

        /**
        * return the generator - g
        */
        public BigInteger G
        {
            get { return g; }
        }

        /**
         * return private value limit - l
         */
        public int L
        {
            get { return l; }
        }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            ElGamalParameters other = obj as ElGamalParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected bool Equals(
            ElGamalParameters other)
        {
            return p.Equals(other.p) && g.Equals(other.g) && l == other.l;
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return p.GetHashCode() ^ g.GetHashCode() ^ l;
        }
    }
}
