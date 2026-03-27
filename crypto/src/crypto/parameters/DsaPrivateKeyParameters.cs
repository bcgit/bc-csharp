using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Digital Signature Algorithm (DSA) private key parameters.</summary>
    public class DsaPrivateKeyParameters
		: DsaKeyParameters
    {
        private readonly BigInteger x;

        /// <summary>Initializes a new instance of <see cref="DsaPrivateKeyParameters"/>.</summary>
        /// <param name="x">The private value X.</param>
        /// <param name="parameters">The DSA domain parameters.</param>
		public DsaPrivateKeyParameters(
            BigInteger		x,
            DsaParameters	parameters)
			: base(true, parameters)
        {
			if (x == null)
				throw new ArgumentNullException("x");

			this.x = x;
        }

        /// <summary>Gets the private value X.</summary>
		public BigInteger X => x;

		public override bool Equals(
			object obj)
        {
			if (obj == this)
				return true;

			DsaPrivateKeyParameters other = obj as DsaPrivateKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			DsaPrivateKeyParameters other)
		{
			return x.Equals(other.x) && base.Equals(other);
		}

		public override int GetHashCode()
        {
            return x.GetHashCode() ^ base.GetHashCode();
        }
    }
}
