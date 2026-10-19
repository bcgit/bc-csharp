using System;

namespace Org.BouncyCastle.Asn1.UA
{
    /// <summary>The binary field parameters of DSTU 4145-2002.</summary>
    public class Dstu4145BinaryField
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Dstu4145BinaryField"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Dstu4145BinaryField"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Dstu4145BinaryField"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Dstu4145BinaryField GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145BinaryField dstu4145BinaryField)
                return dstu4145BinaryField;
            return new Dstu4145BinaryField(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Dstu4145BinaryField"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Dstu4145BinaryField"/>.</returns>
        public static Dstu4145BinaryField GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145BinaryField(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Dstu4145BinaryField"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Dstu4145BinaryField"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="Dstu4145BinaryField"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Dstu4145BinaryField"/>.</returns>
        public static Dstu4145BinaryField GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145BinaryField(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly int m_m, m_k, m_j, m_l;

        private Dstu4145BinaryField(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_m = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).IntPositiveValueExact;

            // TODO[asn1] Asn1Utilities helper method for this type of situation
            var exponents = Asn1Utilities.Read(seq, ref pos, element => element);

            if (DerInteger.GetOptional(exponents) is DerInteger trinomial)
            {
                m_k = trinomial.IntPositiveValueExact;
                m_j = 0;
                m_l = 0;
            }
            else if (Asn1Sequence.GetOptional(exponents) is Asn1Sequence pentanomial)
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

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Dstu4145BinaryField"/>.</summary>
        /// <param name="m">The m.</param>
        /// <param name="k">The k.</param>
        public Dstu4145BinaryField(int m, int k)
            : this(m, k, 0, 0)
        {
        }

        /// <summary>Create a new <see cref="Dstu4145BinaryField"/>.</summary>
        /// <param name="m">The m.</param>
        /// <param name="k">The k.</param>
        /// <param name="j">The j.</param>
        /// <param name="l">The l.</param>
        public Dstu4145BinaryField(int m, int k, int j, int l)
        {
            m_m = m;
            m_k = k;
            m_j = j;
            m_l = l;
        }

        /// <summary>Gets the m.</summary>
        public int M => m_m;

        /// <summary>Gets the k.</summary>
        public int K => m_k;

        /// <summary>Gets the j.</summary>
        public int J => m_j;

        /// <summary>Gets the l.</summary>
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
            DerInteger m = DerInteger.ValueOf(m_m);
            DerInteger k = DerInteger.ValueOf(m_k);

            Asn1Encodable exponents = k;
            if (m_j != 0 || m_l != 0)
            {
                // Pentanomial

                DerInteger j = DerInteger.ValueOf(m_j);
                DerInteger l = DerInteger.ValueOf(m_l);

                exponents = new DerSequence(k, j, l);
            }

            return new DerSequence(m, exponents);
        }
    }
}
