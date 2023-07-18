using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities;

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

		public static TimeStampResp GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
            return new TimeStampResp(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly PkiStatusInfo m_pkiStatusInfo;
        private readonly ContentInfo m_timeStampToken;

        private TimeStampResp(Asn1Sequence seq)
		{
			m_pkiStatusInfo = PkiStatusInfo.GetInstance(seq[0]);

			if (seq.Count > 1)
			{
				m_timeStampToken = ContentInfo.GetInstance(seq[1]);
			}
		}

		public TimeStampResp(PkiStatusInfo pkiStatusInfo, ContentInfo timeStampToken)
		{
			m_pkiStatusInfo = pkiStatusInfo;
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
            Asn1EncodableVector v = new Asn1EncodableVector(2);
			v.Add(m_pkiStatusInfo);
            v.AddOptional(m_timeStampToken);
            return new DerSequence(v);
        }
	}
}
