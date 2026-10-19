using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>DSA domain parameters.</summary>
    // TODO[api] Don't implement ICipherParameters
    public class DsaParameters
        : ICipherParameters
    {
        private readonly BigInteger p, q , g;
        private readonly DsaValidationParameters validation;

        /// <summary>Create a new <see cref="DsaParameters"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="g">The g.</param>
        public DsaParameters(
            BigInteger p,
            BigInteger q,
            BigInteger g)
            : this(p, q, g, null)
        {
        }

        /// <summary>Create a new <see cref="DsaParameters"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="g">The g.</param>
        /// <param name="parameters">The parameters.</param>
        public DsaParameters(
            BigInteger p,
            BigInteger q,
            BigInteger g,
            DsaValidationParameters parameters)
        {
            if (p == null)
                throw new ArgumentNullException("p");
            if (q == null)
                throw new ArgumentNullException("q");
            if (g == null)
                throw new ArgumentNullException("g");

            this.p = p;
            this.q = q;
            this.g = g;
            this.validation = parameters;
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

        /// <summary>Gets the g.</summary>
        public BigInteger G
        {
            get { return g; }
        }

        /// <summary>Gets the validation parameters.</summary>
        public DsaValidationParameters ValidationParameters
        {
            get { return validation; }
        }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            DsaParameters other = obj as DsaParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(
            DsaParameters other)
        {
            return p.Equals(other.p) && q.Equals(other.q) && g.Equals(other.g);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return p.GetHashCode() ^ q.GetHashCode() ^ g.GetHashCode();
        }
    }
}
