namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>Parser for the TimeStampedData structure of RFC 5544.</summary>
    public class TimeStampedDataParser
    {
        /// <summary>Return an <see cref="TimeStampedDataParser"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TimeStampedDataParser"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TimeStampedDataParser"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TimeStampedDataParser GetInstance(object obj)
        {
            if (obj is Asn1SequenceParser parser)
                return new TimeStampedDataParser(parser);

            if (obj is Asn1Sequence seq)
                return new TimeStampedDataParser(seq.Parser);

            return null;
        }

        private readonly Asn1SequenceParser m_parser;

        private DerInteger m_version;
        private DerIA5String m_dataUri;
        private MetaData m_metaData;
        private Asn1OctetStringParser m_content;
        private Evidence m_temporalEvidence;

        private TimeStampedDataParser(Asn1SequenceParser parser)
        {
            m_parser = parser;

            m_version = DerInteger.GetInstance(parser.ReadObject());

            Asn1Object obj = parser.ReadObject().ToAsn1Object();

            if (obj is DerIA5String dataUri)
            {
                m_dataUri = dataUri;
                obj = parser.ReadObject().ToAsn1Object();
            }

            if (//obj is MetaData ||
                obj is Asn1SequenceParser metaDataParser)
            {
                m_metaData = MetaData.GetInstance(metaDataParser);
                obj = parser.ReadObject().ToAsn1Object();
            }

            if (obj is Asn1OctetStringParser content)
            {
                m_content = content;
            }
        }

        /// <summary>Gets the data uri.</summary>
        public virtual DerIA5String DataUri => m_dataUri;

        /// <summary>Gets the meta data.</summary>
        public virtual MetaData MetaData => m_metaData;

        /// <summary>Gets the content.</summary>
        public virtual Asn1OctetStringParser Content => m_content;

        /// <summary>Return the temporal evidence.</summary>
        public virtual Evidence GetTemporalEvidence()
        {
            if (m_temporalEvidence == null)
            {
                m_temporalEvidence = Evidence.GetInstance(m_parser.ReadObject().ToAsn1Object());
            }

            return m_temporalEvidence;
        }
    }
}
