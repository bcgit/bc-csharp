using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>A GOST R 34.10-94 public key.</summary>
    public class Gost3410PublicKeyParameters
        : Gost3410KeyParameters
    {
        private readonly BigInteger y;

        /// <summary>Create a new <see cref="Gost3410PublicKeyParameters"/>.</summary>
        /// <param name="y">The second operand.</param>
        /// <param name="parameters">The parameters.</param>
        public Gost3410PublicKeyParameters(
            BigInteger y,
            Gost3410Parameters parameters)
            : base(false, parameters)
        {
            if (y.SignValue < 1 || y.CompareTo(Parameters.P) >= 0)
                throw new ArgumentException("Invalid y for GOST3410 public key", "y");

            this.y = y;
        }

        /// <summary>Create a new <see cref="Gost3410PublicKeyParameters"/>.</summary>
        /// <param name="y">The second operand.</param>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        public Gost3410PublicKeyParameters(
            BigInteger y,
            DerObjectIdentifier publicKeyParamSet)
            : base(false, publicKeyParamSet)
        {
            if (y.SignValue < 1 || y.CompareTo(Parameters.P) >= 0)
                throw new ArgumentException("Invalid y for GOST3410 public key", "y");

            this.y = y;
        }

        /// <summary>Gets the y.</summary>
        public BigInteger Y
        {
            get { return y; }
        }
    }
}
