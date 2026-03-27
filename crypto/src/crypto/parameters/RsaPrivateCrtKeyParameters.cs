using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>RSA key parameters for use with the Chinese Remainder Theorem.</summary>
    public class RsaPrivateCrtKeyParameters
        : RsaKeyParameters
    {
        private readonly BigInteger e, p, q, dP, dQ, qInv;

        /// <summary>Initializes a new instance of <see cref="RsaPrivateCrtKeyParameters"/>.</summary>
        /// <param name="modulus">The RSA modulus.</param>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="privateExponent">The private exponent.</param>
        /// <param name="p">The first prime factor (p) of the modulus.</param>
        /// <param name="q">The second prime factor (q) of the modulus.</param>
        /// <param name="dP">The CRT exponent for prime p.</param>
        /// <param name="dQ">The CRT exponent for prime q.</param>
        /// <param name="qInv">The CRT coefficient (inverse of q mod p).</param>
        public RsaPrivateCrtKeyParameters(
            BigInteger modulus,
            BigInteger publicExponent,
            BigInteger privateExponent,
            BigInteger p,
            BigInteger q,
            BigInteger dP,
            BigInteger dQ,
            BigInteger qInv)
            : base(true, modulus, privateExponent)
        {
            ValidateValue(publicExponent, "publicExponent", "exponent");
            ValidateValue(p, "p", "P value");
            ValidateValue(q, "q", "Q value");
            ValidateValue(dP, "dP", "DP value");
            ValidateValue(dQ, "dQ", "DQ value");
            ValidateValue(qInv, "qInv", "InverseQ value");

            this.e = publicExponent;
            this.p = p;
            this.q = q;
            this.dP = dP;
            this.dQ = dQ;
            this.qInv = qInv;
        }

        public RsaPrivateCrtKeyParameters(RsaPrivateKeyStructure rsaPrivateKey)
            : this(
                rsaPrivateKey.Modulus,
                rsaPrivateKey.PublicExponent,
                rsaPrivateKey.PrivateExponent,
                rsaPrivateKey.Prime1,
                rsaPrivateKey.Prime2,
                rsaPrivateKey.Exponent1,
                rsaPrivateKey.Exponent2,
                rsaPrivateKey.Coefficient)
        {
        }

        /// <summary>Gets the public exponent.</summary>
        public BigInteger PublicExponent
        {
            get { return e; }
        }

        /// <summary>Gets the first prime factor (p) of the modulus.</summary>
        public BigInteger P
        {
            get { return p; }
        }

        /// <summary>Gets the second prime factor (q) of the modulus.</summary>
        public BigInteger Q
        {
            get { return q; }
        }

        /// <summary>Gets the CRT exponent for prime p.</summary>
        public BigInteger DP
        {
            get { return dP; }
        }

        /// <summary>Gets the CRT exponent for prime q.</summary>
        public BigInteger DQ
        {
            get { return dQ; }
        }

        /// <summary>Gets the CRT coefficient (inverse of q mod p).</summary>
        public BigInteger QInv
        {
            get { return qInv; }
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            RsaPrivateCrtKeyParameters kp = obj as RsaPrivateCrtKeyParameters;

            if (kp == null)
                return false;

            return kp.DP.Equals(dP)
                && kp.DQ.Equals(dQ)
                && kp.Exponent.Equals(this.Exponent)
                && kp.Modulus.Equals(this.Modulus)
                && kp.P.Equals(p)
                && kp.Q.Equals(q)
                && kp.PublicExponent.Equals(e)
                && kp.QInv.Equals(qInv);
        }

        public override int GetHashCode()
        {
            return DP.GetHashCode() ^ DQ.GetHashCode() ^ Exponent.GetHashCode() ^ Modulus.GetHashCode()
                ^ P.GetHashCode() ^ Q.GetHashCode() ^ PublicExponent.GetHashCode() ^ QInv.GetHashCode();
        }

        private static void ValidateValue(BigInteger x, string name, string desc)
        {
            if (x == null)
                throw new ArgumentNullException(name);
            if (x.SignValue <= 0)
                throw new ArgumentException("Not a valid RSA " + desc, name);
        }
    }
}
