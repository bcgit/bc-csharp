using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>ElGamal private key parameters.</summary>
    public class ElGamalPrivateKeyParameters
		: ElGamalKeyParameters
    {
        private readonly BigInteger x;

        /// <summary>Initializes a new instance of <see cref="ElGamalPrivateKeyParameters"/>.</summary>
        /// <param name="x">The private value X.</param>
        /// <param name="parameters">The ElGamal domain parameters.</param>
		public ElGamalPrivateKeyParameters(
            BigInteger			x,
            ElGamalParameters	parameters)
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

			ElGamalPrivateKeyParameters other = obj as ElGamalPrivateKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
		}

		protected bool Equals(
			ElGamalPrivateKeyParameters other)
		{
			return other.x.Equals(x) && base.Equals(other);
		}

		public override int GetHashCode()
		{
			return x.GetHashCode() ^ base.GetHashCode();
		}
    }
}
