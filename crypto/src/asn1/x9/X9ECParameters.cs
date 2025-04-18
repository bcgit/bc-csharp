using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ASN.1 definition for Elliptic-Curve ECParameters structure. See X9.62 for further details.
     */
    public class X9ECParameters
        : Asn1Encodable
    {
        public static X9ECParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is X9ECParameters x9ECParameters)
                return x9ECParameters;
#pragma warning disable CS0618 // Type or member is obsolete
            return new X9ECParameters(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static X9ECParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new X9ECParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static X9ECParameters GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is X9ECParameters x9ECParameters)
                return x9ECParameters;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                return new X9ECParameters(asn1Sequence);
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return null;
        }

        public static X9ECParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new X9ECParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly X9FieldID m_fieldID;
        private readonly X9Curve m_curve;
        private readonly X9ECPoint m_g;
        private readonly BigInteger m_n;
        private readonly BigInteger m_h;

        [Obsolete("Use 'GetInstance' instead")]
        public X9ECParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            DerInteger version = DerInteger.GetInstance(seq[pos++]);
            m_fieldID = X9FieldID.GetInstance(seq[pos++]);
            var x9CurveSequence = Asn1Sequence.GetInstance(seq[pos++]);
            var p = seq[pos++];
            m_n = DerInteger.GetInstance(seq[pos++]).Value;
            m_h = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional)?.Value;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!version.HasValue(1))
                throw new ArgumentException("bad version in X9ECParameters");

            m_curve = new X9Curve(m_fieldID, m_n, m_h, x9CurveSequence);

            if (p is X9ECPoint x9ECPoint)
            {
                m_g = x9ECPoint;
            }
            else
            {
                m_g = new X9ECPoint(m_curve.Curve, Asn1OctetString.GetInstance(p));
            }
        }

        public X9ECParameters(ECCurve curve, X9ECPoint g, BigInteger n)
            : this(curve, g, n, (BigInteger)null, (DerBitString)null)
        {
        }

        public X9ECParameters(ECCurve curve, X9ECPoint g, BigInteger n, BigInteger h)
            : this(curve, g, n, h, (DerBitString)null)
        {
        }

        public X9ECParameters(ECCurve curve, X9ECPoint g, BigInteger n, BigInteger h, byte[] seed)
            : this(curve, g, n, h, DerBitString.FromContentsOptional(seed))
        {
        }

        public X9ECParameters(ECCurve curve, X9ECPoint g, BigInteger n, BigInteger h, DerBitString seed)
        {
            m_curve = new X9Curve(curve, seed);
            m_g = g;
            m_n = n;
            m_h = h;

            IFiniteField field = curve.Field;
            if (ECAlgorithms.IsFpField(field))
            {
                m_fieldID = new X9FieldID(field.Characteristic);
            }
            else if (ECAlgorithms.IsF2mField(field))
            {
                IPolynomialExtensionField f2mField = (IPolynomialExtensionField)field;
                int[] exponents = f2mField.MinimalPolynomial.GetExponentsPresent();
                if (exponents.Length == 3)
                {
                    m_fieldID = new X9FieldID(exponents[2], exponents[1]);
                }
                else if (exponents.Length == 5)
                {
                    m_fieldID = new X9FieldID(exponents[4], exponents[1], exponents[2], exponents[3]);
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

        public ECCurve Curve => m_curve.Curve;

        public ECPoint G => m_g.Point;

        public BigInteger N => m_n;

        public BigInteger H => m_h;

        public byte[] GetSeed() => m_curve.GetSeed();

        public DerBitString Seed => m_curve.Seed;

        /**
         * Return the ASN.1 entry representing the Curve.
         *
         * @return the X9Curve for the curve in these parameters.
         */
        public X9Curve CurveEntry => m_curve;

        /**
         * Return the ASN.1 entry representing the FieldID.
         *
         * @return the X9FieldID for the FieldID in these parameters.
         */
        public X9FieldID FieldIDEntry => m_fieldID;

        /**
         * Return the ASN.1 entry representing the base point G.
         *
         * @return the X9ECPoint for the base point in these parameters.
         */
        public X9ECPoint BaseEntry => m_g;

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
            Asn1EncodableVector v = new Asn1EncodableVector(6);
            v.Add(DerInteger.One, m_fieldID, m_curve, m_g, new DerInteger(m_n));

            if (m_h != null)
            {
                v.Add(new DerInteger(m_h));
            }

            return new DerSequence(v);
        }
    }
}
