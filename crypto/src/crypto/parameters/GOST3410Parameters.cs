using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>GOST R 34.10-94 domain parameters.</summary>
    // TODO[api] Don't implement ICipherParameters
    public class Gost3410Parameters
        : ICipherParameters
    {
        private readonly BigInteger p, q, a;
        private readonly Gost3410ValidationParameters validation;

        /// <summary>Create a new <see cref="Gost3410Parameters"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="a">The first operand.</param>
        public Gost3410Parameters(
            BigInteger p,
            BigInteger q,
            BigInteger a)
            : this(p, q, a, null)
        {
        }

        /// <summary>Create a new <see cref="Gost3410Parameters"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="a">The first operand.</param>
        /// <param name="validation">The validation.</param>
        public Gost3410Parameters(
            BigInteger p,
            BigInteger q,
            BigInteger a,
            Gost3410ValidationParameters validation)
        {
            if (p == null)
                throw new ArgumentNullException("p");
            if (q == null)
                throw new ArgumentNullException("q");
            if (a == null)
                throw new ArgumentNullException("a");

            this.p = p;
            this.q = q;
            this.a = a;
            this.validation = validation;
        }

        /// <summary>Gets the p.</summary>
        public BigInteger P
        {
            get { return p; }
        }

        /// <summary>Gets the q.</summary>
        public BigInteger Q
        {
            get { return q; }
        }

        /// <summary>Gets the a.</summary>
        public BigInteger A
        {
            get { return a; }
        }

        /// <summary>Gets the validation parameters.</summary>
        public Gost3410ValidationParameters ValidationParameters
        {
            get { return validation; }
        }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            Gost3410Parameters other = obj as Gost3410Parameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected bool Equals(
            Gost3410Parameters other)
        {
            return p.Equals(other.p) && q.Equals(other.q) && a.Equals(other.a);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return p.GetHashCode() ^ q.GetHashCode() ^ a.GetHashCode();
        }
    }
}
