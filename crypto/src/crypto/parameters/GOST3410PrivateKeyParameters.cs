using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>A GOST R 34.10-94 private key.</summary>
    public class Gost3410PrivateKeyParameters
        : Gost3410KeyParameters
    {
        private readonly BigInteger x;

        /// <summary>Create a new <see cref="Gost3410PrivateKeyParameters"/>.</summary>
        /// <param name="x">The first operand.</param>
        /// <param name="parameters">The parameters.</param>
        public Gost3410PrivateKeyParameters(
            BigInteger x,
            Gost3410Parameters parameters)
            : base(true, parameters)
        {
            if (x.SignValue < 1 || x.BitLength > 256 || x.CompareTo(Parameters.Q) >= 0)
                throw new ArgumentException("Invalid x for GOST3410 private key", "x");

            this.x = x;
        }

        /// <summary>Create a new <see cref="Gost3410PrivateKeyParameters"/>.</summary>
        /// <param name="x">The first operand.</param>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        public Gost3410PrivateKeyParameters(
            BigInteger x,
            DerObjectIdentifier publicKeyParamSet)
            : base(true, publicKeyParamSet)
        {
            if (x.SignValue < 1 || x.BitLength > 256 || x.CompareTo(Parameters.Q) >= 0)
                throw new ArgumentException("Invalid x for GOST3410 private key", "x");

            this.x = x;
        }

        /// <summary>Gets the x.</summary>
        public BigInteger X
        {
            get { return x; }
        }
    }
}
