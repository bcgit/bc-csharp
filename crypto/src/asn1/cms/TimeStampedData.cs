using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	public class TimeStampedData
		: Asn1Encodable
	{
        public static TimeStampedData GetInstance(object obj)
        {
			if (obj == null)
				return null;
			if (obj is TimeStampedData timeStampedData)
				return timeStampedData;
            return new TimeStampedData(Asn1Sequence.GetInstance(obj));
        }

        public static TimeStampedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new TimeStampedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_version;
        private readonly DerIA5String m_dataUri;
        private readonly MetaData m_metaData;
        private readonly Asn1OctetString m_content;
        private readonly Evidence m_temporalEvidence;

        public TimeStampedData(DerIA5String dataUri, MetaData metaData, Asn1OctetString content,
            Evidence temporalEvidence)
        {
            m_version = DerInteger.One;
            m_dataUri = dataUri;
            m_metaData = metaData;
            m_content = content;
            m_temporalEvidence = temporalEvidence ?? throw new ArgumentNullException(nameof(temporalEvidence));
        }

        private TimeStampedData(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_dataUri = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);
            m_metaData = Asn1Utilities.ReadOptional(seq, ref pos, MetaData.GetOptional);
            m_content = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);
            m_temporalEvidence = Evidence.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual DerIA5String DataUri => m_dataUri;

        public MetaData MetaData => m_metaData;

        public Asn1OctetString Content => m_content;

        public Evidence TemporalEvidence => m_temporalEvidence;

		/**
		 * <pre>
		 * TimeStampedData ::= SEQUENCE {
		 *   version              INTEGER { v1(1) },
		 *   dataUri              IA5String OPTIONAL,
		 *   metaData             MetaData OPTIONAL,
		 *   content              OCTET STRING OPTIONAL,
		 *   temporalEvidence     Evidence
		 * }
		 * </pre>
		 * @return
		 */
		public override Asn1Object ToAsn1Object()
		{
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_version);
			v.AddOptional(m_dataUri, m_metaData, m_content);
			v.Add(m_temporalEvidence);
			return new BerSequence(v);
		}
	}
}
