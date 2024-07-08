using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class TimeStampAndCrl
		: Asn1Encodable
	{
        public static TimeStampAndCrl GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is TimeStampAndCrl timeStampAndCrl)
                return timeStampAndCrl;
            return new TimeStampAndCrl(Asn1Sequence.GetInstance(obj));
        }

        public static TimeStampAndCrl GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampAndCrl(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static TimeStampAndCrl GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampAndCrl(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo m_timeStamp;
		private readonly CertificateList m_crl;

		public TimeStampAndCrl(ContentInfo timeStamp)
			: this(timeStamp, null)
		{
		}

        public TimeStampAndCrl(ContentInfo timeStamp, CertificateList crl)
        {
            m_timeStamp = timeStamp ?? throw new ArgumentNullException(nameof(timeStamp));
            m_crl = crl;
        }

        private TimeStampAndCrl(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_timeStamp = ContentInfo.GetInstance(seq[pos++]);
            m_crl = Asn1Utilities.ReadOptional(seq, ref pos, CertificateList.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public virtual ContentInfo TimeStampToken => m_timeStamp;

		public virtual CertificateList Crl => m_crl;

		/**
		 * <pre>
		 * TimeStampAndCRL ::= SEQUENCE {
		 *     timeStamp   TimeStampToken,          -- according to RFC 3161
		 *     crl         CertificateList OPTIONAL -- according to RFC 5280
		 *  }
		 * </pre>
		 * @return
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_crl == null
				?  new DerSequence(m_timeStamp)
                :  new DerSequence(m_timeStamp, m_crl);
		}
	}
}
