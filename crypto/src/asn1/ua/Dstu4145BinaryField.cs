using System;

namespace Org.BouncyCastle.Asn1.UA
{
    public class Dstu4145BinaryField
        : Asn1Encodable
    {
        public static Dstu4145BinaryField GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145BinaryField dstu4145BinaryField)
                return dstu4145BinaryField;
            return new Dstu4145BinaryField(Asn1Sequence.GetInstance(obj));
        }

        public static Dstu4145BinaryField GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145BinaryField(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Dstu4145BinaryField GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Dstu4145BinaryField dstu4145BinaryField)
                return dstu4145BinaryField;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Dstu4145BinaryField(asn1Sequence);

            return null;
        }

        public static Dstu4145BinaryField GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145BinaryField(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly int m_m, m_k, m_j, m_l;

        private Dstu4145BinaryField(Asn1Sequence seq)
        {
            if (seq.Count != 2)
                throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

            m_m = DerInteger.GetInstance(seq[0]).IntPositiveValueExact;

            if (DerInteger.GetOptional(seq[1]) is var trinomial)
            {
                m_k = trinomial.IntPositiveValueExact;
                m_j = 0;
                m_l = 0;
            }
            else if (Asn1Sequence.GetOptional(seq[1]) is var pentanomial)
            {
                if (pentanomial.Count != 3)
                    throw new ArgumentException("Bad sequence size (Pentanomial): " + pentanomial.Count, nameof(seq));

                m_k = DerInteger.GetInstance(pentanomial[0]).IntPositiveValueExact;
                m_j = DerInteger.GetInstance(pentanomial[1]).IntPositiveValueExact;
                m_l = DerInteger.GetInstance(pentanomial[2]).IntPositiveValueExact;
            }
            else
            {
                throw new ArgumentException("object parse error", nameof(seq));
            }
        }

        public Dstu4145BinaryField(int m, int k)
            : this(m, k, 0, 0)
        {
        }

        public Dstu4145BinaryField(int m, int k, int j, int l)
        {
            m_m = m;
            m_k = k;
            m_j = j;
            m_l = l;
        }

        public int M => m_m;

        public int K => m_k;

        public int J => m_j;

        public int L => m_l;

        /**
         * BinaryField ::= SEQUENCE {
         * M INTEGER,
         * CHOICE {Trinomial,    Pentanomial}
         * Trinomial::= INTEGER
         * Pentanomial::= SEQUENCE {
         * k INTEGER,
         * j INTEGER,
         * l INTEGER}
         */
        public override Asn1Object ToAsn1Object()
        {
            DerInteger m = new DerInteger(m_m);
            DerInteger k = new DerInteger(m_k);

            Asn1Encodable exponents = k;
            if (m_j != 0 || m_l != 0)
            {
                // Pentanomial

                DerInteger j = new DerInteger(m_j);
                DerInteger l = new DerInteger(m_l);

                exponents = new DerSequence(k, j, l);
            }

            return new DerSequence(m, exponents);
        }
    }
}
