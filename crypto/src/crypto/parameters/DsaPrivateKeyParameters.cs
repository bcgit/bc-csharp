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
            if (x == null)
                throw new ArgumentNullException(nameof(x));

            m_x = x;
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
