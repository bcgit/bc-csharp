using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ASN.1 def for Elliptic-Curve Field ID structure. See
     * X9.62, for further details.
     */
    public class X9FieldID
        : Asn1Encodable
    {
        public static X9FieldID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is X9FieldID x9FieldID)
                return x9FieldID;
            return new X9FieldID(Asn1Sequence.GetInstance(obj));
        }

        public static X9FieldID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X9FieldID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static X9FieldID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X9FieldID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_id;
        private readonly Asn1Object m_parameters;

        private X9FieldID(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_id = DerObjectIdentifier.GetInstance(seq[0]);
            m_parameters = seq[1].ToAsn1Object();
        }

        /**
         * Constructor for elliptic curves over prime fields
         * <code>F<sub>2</sub></code>.
         * @param primeP The prime <code>p</code> defining the prime field.
         */
        public X9FieldID(BigInteger primeP)
        {
            m_id = X9ObjectIdentifiers.PrimeField;
            m_parameters = new DerInteger(primeP);
        }

        /**
         * Constructor for elliptic curves over binary fields
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         */
        public X9FieldID(int m, int k1)
            : this(m, k1, 0, 0)
        {
        }

        /**
         * Constructor for elliptic curves over binary fields
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>..
         */
        public X9FieldID(int m, int k1, int k2, int k3)
        {
            m_id = X9ObjectIdentifiers.CharacteristicTwoField;

            Asn1EncodableVector fieldIdParams = new Asn1EncodableVector(3);
            fieldIdParams.Add(new DerInteger(m));

            if (k2 == 0)
            {
                if (k3 != 0)
                    throw new ArgumentException("inconsistent k values");

                fieldIdParams.Add(
                    X9ObjectIdentifiers.TPBasis,
                    new DerInteger(k1));
            }
            else
            {
                if (k2 <= k1 || k3 <= k2)
                    throw new ArgumentException("inconsistent k values");

                fieldIdParams.Add(
                    X9ObjectIdentifiers.PPBasis,
                    new DerSequence(
                        new DerInteger(k1),
                        new DerInteger(k2),
                        new DerInteger(k3)));
            }

            m_parameters = new DerSequence(fieldIdParams);
        }

        // TODO[api] Rename to 'FieldType'
        public DerObjectIdentifier Identifier => m_id;

        // TODO[api] Return 'Asn1Encodable'
        public Asn1Object Parameters => m_parameters;

        /**
         * Produce a Der encoding of the following structure.
         * <pre>
         *  FieldID ::= Sequence {
         *      fieldType       FIELD-ID.&amp;id({IOSet}),
         *      parameters      FIELD-ID.&amp;Type({IOSet}{&#64;fieldType})
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_id, m_parameters);
    }
}
