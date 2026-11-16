using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Digital Signature Algorithm (DSA) private key parameters.</summary>
    public class DsaPrivateKeyParameters
        : DsaKeyParameters
    {
        private readonly BigInteger m_x;

        /// <summary>Initializes a new instance of <see cref="DsaPrivateKeyParameters"/>.</summary>
        /// <param name="x">The private value X.</param>
        /// <param name="parameters">The DSA domain parameters.</param>
        public DsaPrivateKeyParameters(BigInteger x, DsaParameters parameters)
            : base(true, parameters)
        {
            m_x = Validate(x, parameters);
        }

        private static BigInteger Validate(BigInteger x, DsaParameters parameters)
        {
            if (x == null)
                throw new ArgumentNullException(nameof(x));

            // FIPS 186-4 sec. 4.1: x is in [1, q-1]. Parameters may be null (inherited), leaving nothing to check.
            if (parameters != null && (x.SignValue < 1 || x.CompareTo(parameters.Q) >= 0))
                throw new ArgumentException("x must be in [1, q-1]", nameof(x));

            return x;
        }

        /// <summary>Gets the private value X.</summary>
        public BigInteger X => m_x;

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is DsaPrivateKeyParameters other
                && Equals(other);
        }

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected bool Equals(DsaPrivateKeyParameters other) =>
            m_x.Equals(other.m_x) && base.Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => m_x.GetHashCode() ^ base.GetHashCode();
    }
}
