using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    public class Accuracy
		: Asn1Encodable
	{
        protected const int MinMillis = 1;
        protected const int MaxMillis = 999;
        protected const int MinMicros = 1;
        protected const int MaxMicros = 999;

        public static Accuracy GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Accuracy accuracy)
                return accuracy;
            return new Accuracy(Asn1Sequence.GetInstance(obj));
        }

        public static Accuracy GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Accuracy(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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

        public Accuracy(DerInteger seconds, DerInteger millis, DerInteger micros)
        {
            m_seconds = seconds;
            m_millis = millis;
            m_micros = micros;

            Validate();
        }

        public DerInteger Seconds => m_seconds;

        public DerInteger Millis => m_millis;

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
