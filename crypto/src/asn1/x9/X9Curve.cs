using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ASN.1 def for Elliptic-Curve Curve structure. See X9.62 for further details.
     */
    public class X9Curve
        : Asn1Encodable
    {
        private readonly ECCurve m_curve;
        private readonly DerBitString m_seed;
        private readonly DerObjectIdentifier m_fieldType;

        public X9Curve(ECCurve curve)
            : this(curve, (DerBitString)null)
        {
        }

        public X9Curve(ECCurve curve, byte[] seed)
            : this(curve, DerBitString.FromContentsOptional(seed))
        {
        }

        public X9Curve(ECCurve curve, DerBitString seed)
        {
            m_curve = curve ?? throw new ArgumentNullException(nameof(curve));
            m_seed = seed;

            var field = curve.Field;
            if (ECAlgorithms.IsFpField(field))
            {
                m_fieldType = X9ObjectIdentifiers.PrimeField;
            }
            else if (ECAlgorithms.IsF2mField(field))
            {
                m_fieldType = X9ObjectIdentifiers.CharacteristicTwoField;
            }
            else
            {
                throw new ArgumentException("This type of ECCurve is not implemented");
            }
        }

        public X9Curve(X9FieldID fieldID, BigInteger order, BigInteger cofactor, Asn1Sequence seq)
        {
            if (fieldID == null)
                throw new ArgumentNullException(nameof(fieldID));
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            m_fieldType = fieldID.FieldType;

            if (X9ObjectIdentifiers.PrimeField.Equals(m_fieldType))
            {
                BigInteger p = DerInteger.GetInstance(fieldID.Parameters).Value;
                BigInteger A = new BigInteger(1, Asn1OctetString.GetInstance(seq[0]).GetOctets());
                BigInteger B = new BigInteger(1, Asn1OctetString.GetInstance(seq[1]).GetOctets());
                m_curve = new FpCurve(p, A, B, order, cofactor);
            }
            else if (X9ObjectIdentifiers.CharacteristicTwoField.Equals(m_fieldType)) 
            {
                // Characteristic two field
                Asn1Sequence parameters = Asn1Sequence.GetInstance(fieldID.Parameters);
                int m = DerInteger.GetInstance(parameters[0]).IntValueExact;
                DerObjectIdentifier representation = DerObjectIdentifier.GetInstance(parameters[1]);

                int k1, k2, k3;
                if (X9ObjectIdentifiers.TPBasis.Equals(representation)) 
                {
                    // Trinomial basis representation
                    k1 = DerInteger.GetInstance(parameters[2]).IntValueExact;
                    k2 = 0;
                    k3 = 0;
                }
                else if (X9ObjectIdentifiers.PPBasis.Equals(representation))
                {
                    // Pentanomial basis representation
                    Asn1Sequence pentanomial = Asn1Sequence.GetInstance(parameters[2]);
                    k1 = DerInteger.GetInstance(pentanomial[0]).IntValueExact;
                    k2 = DerInteger.GetInstance(pentanomial[1]).IntValueExact;
                    k3 = DerInteger.GetInstance(pentanomial[2]).IntValueExact;
                }
                else
                {
                    throw new ArgumentException("This CharacteristicTwoField representation is not implemented");
                }

                BigInteger A = new BigInteger(1, Asn1OctetString.GetInstance(seq[0]).GetOctets());
                BigInteger B = new BigInteger(1, Asn1OctetString.GetInstance(seq[1]).GetOctets());
                m_curve = new F2mCurve(m, k1, k2, k3, A, B, order, cofactor);
            }
            else
            {
                throw new ArgumentException("This type of ECCurve is not implemented");
            }

            if (seq.Count == 3)
            {
                m_seed = DerBitString.GetInstance(seq[2]);
            }
        }

        public ECCurve Curve => m_curve;

        public byte[] GetSeed() => m_seed?.GetBytes();

        public DerBitString Seed => m_seed;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  Curve ::= Sequence {
         *      a               FieldElement,
         *      b               FieldElement,
         *      seed            BIT STRING      OPTIONAL
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            var a = new X9FieldElement(m_curve.A);
            var b = new X9FieldElement(m_curve.B);

            return m_seed == null
                ?  new DerSequence(a, b)
                :  new DerSequence(a, b, m_seed);
        }
    }
}
