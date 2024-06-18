using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class TimeStampTokenEvidence
		: Asn1Encodable
	{
        public static TimeStampTokenEvidence GetInstance(object obj)
        {
			if (obj == null)
				return null;
			if (obj is TimeStampTokenEvidence timeStampTokenEvidence)
				return timeStampTokenEvidence;
            return new TimeStampTokenEvidence(Asn1Sequence.GetInstance(obj));
        }

        public static TimeStampTokenEvidence GetInstance(Asn1TaggedObject tagged, bool isExplicit)
        {
            return new TimeStampTokenEvidence(Asn1Sequence.GetInstance(tagged, isExplicit));
        }

        private readonly TimeStampAndCrl[] m_timeStampAndCrls;

		public TimeStampTokenEvidence(TimeStampAndCrl[] timeStampAndCrls)
		{
			if (Arrays.IsNullOrContainsNull(timeStampAndCrls))
                throw new NullReferenceException("'timeStampAndCrls' cannot be null, or contain null");

            m_timeStampAndCrls = timeStampAndCrls;
		}

		public TimeStampTokenEvidence(TimeStampAndCrl timeStampAndCrl)
		{
			m_timeStampAndCrls = new []{ timeStampAndCrl ?? throw new ArgumentNullException(nameof(timeStampAndCrl)) };
		}

		private TimeStampTokenEvidence(Asn1Sequence seq)
		{
			m_timeStampAndCrls = seq.MapElements(TimeStampAndCrl.GetInstance);
		}

        public virtual TimeStampAndCrl[] ToTimeStampAndCrlArray() => (TimeStampAndCrl[])m_timeStampAndCrls.Clone();

		/**
		 * <pre>
		 * TimeStampTokenEvidence ::=
		 *    SEQUENCE SIZE(1..MAX) OF TimeStampAndCrl
		 * </pre>
		 * @return
		 */
		public override Asn1Object ToAsn1Object() => new DerSequence(m_timeStampAndCrls);
	}
}
