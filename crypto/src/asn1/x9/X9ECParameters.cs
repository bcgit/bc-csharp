using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ASN.1 def for Elliptic-Curve ECParameters structure. See
     * X9.62, for further details.
     */
    public class X9ECParameters
        : Asn1Encodable
    {
        private X9FieldID	fieldID;
        private ECCurve		curve;
        private ECPoint		g;
        private BigInteger	n;
        private BigInteger	h;
        private byte[]		seed;

        public X9ECParameters(
            Asn1Sequence seq)
        {
            if (!(seq[0] is DerInteger)
               || !((DerInteger) seq[0]).Value.Equals(BigInteger.One))
            {
                throw new ArgumentException("bad version in X9ECParameters");
            }

            X9Curve x9c = null;
            if (seq[2] is X9Curve)
            {
                x9c = (X9Curve) seq[2];
            }
            else
            {
                x9c = new X9Curve(
                    new X9FieldID(
                        (Asn1Sequence) seq[1]),
                        (Asn1Sequence) seq[2]);
            }

            this.curve = x9c.Curve;

            if (seq[3] is X9ECPoint)
            {
                this.g = ((X9ECPoint) seq[3]).Point;
            }
            else
            {
                this.g = new X9ECPoint(curve, (Asn1OctetString) seq[3]).Point;
            }

            this.n = ((DerInteger) seq[4]).Value;
            this.seed = x9c.GetSeed();

            if (seq.Count == 6)
            {
                this.h = ((DerInteger) seq[5]).Value;
            }
        }

        public X9ECParameters(
            ECCurve		curve,
            ECPoint		g,
            BigInteger	n)
            : this(curve, g, n, BigInteger.One, null)
        {
        }

        public X9ECParameters(
            ECCurve		curve,
            ECPoint		g,
            BigInteger	n,
            BigInteger	h)
            : this(curve, g, n, h, null)
        {
        }

        public X9ECParameters(
            ECCurve		curve,
            ECPoint		g,
            BigInteger	n,
            BigInteger	h,
            byte[]		seed)
        {
            this.curve = curve;
            this.g = g.Normalize();
            this.n = n;
            this.h = h;
            this.seed = seed;

            if (ECAlgorithms.IsFpCurve(curve))
            {
                this.fieldID = new X9FieldID(curve.Field.Characteristic);
            }
            else if (ECAlgorithms.IsF2mCurve(curve))
            {
                IPolynomialExtensionField field = (IPolynomialExtensionField)curve.Field;
                int[] exponents = field.MinimalPolynomial.GetExponentsPresent();
                if (exponents.Length == 3)
                {
                    this.fieldID = new X9FieldID(exponents[2], exponents[1]);
                }
                else if (exponents.Length == 5)
                {
                    this.fieldID = new X9FieldID(exponents[4], exponents[1], exponents[2], exponents[3]);
                }
                else
                {
                    throw new ArgumentException("Only trinomial and pentomial curves are supported");
                }
            }
            else
            {
                throw new ArgumentException("'curve' is of an unsupported type");
            }
        }

        public ECCurve Curve
        {
            get { return curve; }
        }

        public ECPoint G
        {
            get { return g; }
        }

        public BigInteger N
        {
            get { return n; }
        }

        public BigInteger H
        {
            get
            {
                if (h == null)
                {
                    // TODO - this should be calculated, it will cause issues with custom curves.
                    return BigInteger.One;
                }

                return h;
            }
        }

        public byte[] GetSeed()
        {
            return seed;
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  ECParameters ::= Sequence {
         *      version         Integer { ecpVer1(1) } (ecpVer1),
         *      fieldID         FieldID {{FieldTypes}},
         *      curve           X9Curve,
         *      base            X9ECPoint,
         *      order           Integer,
         *      cofactor        Integer OPTIONAL
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(
                new DerInteger(1),
                fieldID,
                new X9Curve(curve, seed),
                new X9ECPoint(g),
                new DerInteger(n));

            if (h != null)
            {
                v.Add(new DerInteger(h));
            }

            return new DerSequence(v);
        }
    }
}
