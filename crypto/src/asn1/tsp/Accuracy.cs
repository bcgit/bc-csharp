using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /// <summary>The Accuracy structure of RFC 3161.</summary>
    public class Accuracy
        : Asn1Encodable
    {
        /// <summary>The <c>MinMillis</c> constant, with the value <c>1</c>.</summary>
        protected const int MinMillis = 1;
        /// <summary>The <c>MaxMillis</c> constant, with the value <c>999</c>.</summary>
        protected const int MaxMillis = 999;
        /// <summary>The <c>MinMicros</c> constant, with the value <c>1</c>.</summary>
        protected const int MinMicros = 1;
        /// <summary>The <c>MaxMicros</c> constant, with the value <c>999</c>.</summary>
        protected const int MaxMicros = 999;

        /// <summary>Return an <see cref="Accuracy"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Accuracy"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Accuracy"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Accuracy GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Accuracy accuracy)
                return accuracy;
            return new Accuracy(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Accuracy"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Accuracy"/>.</returns>
        public static Accuracy GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Accuracy(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Accuracy"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Accuracy"/>, or null if <paramref name="element"/> is null.</returns>
        public static Accuracy GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Accuracy accuracy)
                return accuracy;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Accuracy(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="Accuracy"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Accuracy"/>.</returns>
        public static Accuracy GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Accuracy(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_seconds;
        private readonly DerInteger m_millis;
        private readonly DerInteger m_micros;

        private Accuracy(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_seconds = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_millis = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, DerInteger.GetTagged);
            m_micros = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerInteger.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            Validate();
        }

        /// <summary>Create a new <see cref="Accuracy"/>.</summary>
        /// <param name="seconds">The seconds.</param>
        /// <param name="millis">The millis.</param>
        /// <param name="micros">The micros.</param>
        public Accuracy(DerInteger seconds, DerInteger millis, DerInteger micros)
        {
            m_seconds = seconds;
            m_millis = millis;
            m_micros = micros;

            Validate();
        }

        /// <summary>Gets the seconds.</summary>
        public DerInteger Seconds => m_seconds;

        /// <summary>Gets the millis.</summary>
        public DerInteger Millis => m_millis;

        /// <summary>Gets the micros.</summary>
        public DerInteger Micros => m_micros;

        /**
         * <pre>
         * Accuracy ::= SEQUENCE {
         *             seconds        INTEGER              OPTIONAL,
         *             millis     [0] INTEGER  (1..999)    OPTIONAL,
         *             micros     [1] INTEGER  (1..999)    OPTIONAL
         *             }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptional(m_seconds);
            v.AddOptionalTagged(false, 0, m_millis);
            v.AddOptionalTagged(false, 1, m_micros);
            return new DerSequence(v);
        }

        private void Validate()
        {
            if (m_millis != null)
            {
                int millisValue = m_millis.IntValueExact;
                if (millisValue < MinMillis || millisValue > MaxMillis)
                    throw new ArgumentException("Invalid millis field : not in (1..999)");
            }
            if (m_micros != null)
            {
                int microsValue = m_micros.IntValueExact;
                if (microsValue < MinMicros || microsValue > MaxMicros)
                    throw new ArgumentException("Invalid micros field : not in (1..999)");
            }
        }
    }
}
