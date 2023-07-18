using System;

using Org.BouncyCastle.Utilities;

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

        public static Accuracy GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new Accuracy(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_seconds;
        private readonly DerInteger m_millis;
        private readonly DerInteger m_micros;

        public Accuracy(DerInteger seconds, DerInteger millis, DerInteger micros)
        {
            if (null != millis)
            {
                int millisValue = millis.IntValueExact;
                if (millisValue < MinMillis || millisValue > MaxMillis)
                    throw new ArgumentException("Invalid millis field : not in (1..999)");
            }
            if (null != micros)
            {
                int microsValue = micros.IntValueExact;
                if (microsValue < MinMicros || microsValue > MaxMicros)
                    throw new ArgumentException("Invalid micros field : not in (1..999)");
            }

            m_seconds = seconds;
            m_millis = millis;
            m_micros = micros;
        }

        private Accuracy(Asn1Sequence seq)
        {
            DerInteger seconds = null;
            DerInteger millis = null;
            DerInteger micros = null;

            for (int i = 0; i < seq.Count; ++i)
            {
                // seconds
                if (seq[i] is DerInteger derInteger)
                {
                    seconds = derInteger;
                }
                else if (seq[i] is Asn1TaggedObject extra)
                {
                    switch (extra.TagNo)
                    {
                    case 0:
                        millis = DerInteger.GetInstance(extra, false);
                        int millisValue = millis.IntValueExact;
                        if (millisValue < MinMillis || millisValue > MaxMillis)
                            throw new ArgumentException("Invalid millis field : not in (1..999)");
                        break;
                    case 1:
                        micros = DerInteger.GetInstance(extra, false);
                        int microsValue = micros.IntValueExact;
                        if (microsValue < MinMicros || microsValue > MaxMicros)
                            throw new ArgumentException("Invalid micros field : not in (1..999)");
                        break;
                    default:
                        throw new ArgumentException("Invalid tag number");
                    }
                }
            }

            m_seconds = seconds;
            m_millis = millis;
            m_micros = micros;
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
    }
}
