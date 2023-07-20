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

        private TimeStampAndCrl[] timeStampAndCrls;

		public TimeStampTokenEvidence(TimeStampAndCrl[] timeStampAndCrls)
		{
			this.timeStampAndCrls = timeStampAndCrls;
		}

		public TimeStampTokenEvidence(TimeStampAndCrl timeStampAndCrl)
		{
			this.timeStampAndCrls = new TimeStampAndCrl[]{ timeStampAndCrl };
		}

		private TimeStampTokenEvidence(Asn1Sequence seq)
		{
			this.timeStampAndCrls = new TimeStampAndCrl[seq.Count];

			int count = 0;

			foreach (Asn1Encodable ae in seq)
			{
				this.timeStampAndCrls[count++] = TimeStampAndCrl.GetInstance(ae.ToAsn1Object());
			}
		}

        public virtual TimeStampAndCrl[] ToTimeStampAndCrlArray()
		{
			return (TimeStampAndCrl[])timeStampAndCrls.Clone();
		}

		/**
		 * <pre>
		 * TimeStampTokenEvidence ::=
		 *    SEQUENCE SIZE(1..MAX) OF TimeStampAndCrl
		 * </pre>
		 * @return
		 */
		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(timeStampAndCrls);
		}
	}
}
