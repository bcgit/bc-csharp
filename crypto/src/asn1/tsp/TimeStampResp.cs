using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Tsp
{
    public class TimeStampResp
		: Asn1Encodable
	{
        public static TimeStampResp GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampResp timeStampResp)
                return timeStampResp;
            return new TimeStampResp(Asn1Sequence.GetInstance(obj));
        }

		public static TimeStampResp GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampResp(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static TimeStampResp GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampResp(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PkiStatusInfo m_pkiStatusInfo;
        private readonly ContentInfo m_timeStampToken;

        private TimeStampResp(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_pkiStatusInfo = PkiStatusInfo.GetInstance(seq[0]);

			if (seq.Count > 1)
			{
				m_timeStampToken = ContentInfo.GetInstance(seq[1]);
			}
		}

		public TimeStampResp(PkiStatusInfo pkiStatusInfo, ContentInfo timeStampToken)
		{
			m_pkiStatusInfo = pkiStatusInfo ?? throw new ArgumentNullException(nameof(pkiStatusInfo));
			m_timeStampToken = timeStampToken;
		}

		public PkiStatusInfo Status => m_pkiStatusInfo;

		public ContentInfo TimeStampToken => m_timeStampToken;

		/**
		 * <pre>
		 * TimeStampResp ::= SEQUENCE  {
		 *   status                  PkiStatusInfo,
		 *   timeStampToken          TimeStampToken     OPTIONAL  }
		 * </pre>
		 */
        public override Asn1Object ToAsn1Object()
        {
            return m_timeStampToken == null
                ?  new DerSequence(m_pkiStatusInfo)
                :  new DerSequence(m_pkiStatusInfo, m_timeStampToken);
        }
	}
}
