using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Digital Signature Algorithm (DSA) public key parameters.</summary>
    public class DsaPublicKeyParameters
		: DsaKeyParameters
    {
        private static BigInteger Validate(BigInteger y, DsaParameters parameters)
        {
            // we can't validate without params, fortunately we can't use the key either...
            if (parameters != null)
            {
                if (y.CompareTo(BigInteger.Two) < 0
                    || y.CompareTo(parameters.P.Subtract(BigInteger.Two)) > 0
                    || !y.ModPow(parameters.Q, parameters.P).Equals(BigInteger.One))
                {
                    throw new ArgumentException("y value does not appear to be in correct group");
                }
            }

            return y;
        }

        private readonly BigInteger y;

        /// <summary>Initializes a new instance of <see cref="DsaPublicKeyParameters"/>.</summary>
        /// <param name="y">The public value Y.</param>
        /// <param name="parameters">The DSA domain parameters.</param>
		public DsaPublicKeyParameters(
            BigInteger		y,
            DsaParameters	parameters)
			: base(false, parameters)
        {
			if (y == null)
				throw new ArgumentNullException("y");

			this.y = Validate(y, parameters);
        }

        /// <summary>Gets the public value Y.</summary>
		public BigInteger Y => y;

		public override bool Equals(object obj)
        {
			if (obj == this)
				return true;

			DsaPublicKeyParameters other = obj as DsaPublicKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			DsaPublicKeyParameters other)
		{
			return y.Equals(other.y) && base.Equals(other);
		}

		public override int GetHashCode()
        {
			return y.GetHashCode() ^ base.GetHashCode();
        }
    }
}
