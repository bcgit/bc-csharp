using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The TimeStampedData structure of RFC 5544.</summary>
    public class TimeStampedData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="TimeStampedData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TimeStampedData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TimeStampedData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TimeStampedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampedData timeStampedData)
                return timeStampedData;
            return new TimeStampedData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TimeStampedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampedData"/>.</returns>
        public static TimeStampedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="TimeStampedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TimeStampedData"/>.</returns>
        public static TimeStampedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly DerIA5String m_dataUri;
        private readonly MetaData m_metaData;
        private readonly Asn1OctetString m_content;
        private readonly Evidence m_temporalEvidence;

        /// <summary>Create a new <see cref="TimeStampedData"/>.</summary>
        /// <param name="dataUri">The data uri.</param>
        /// <param name="metaData">The meta data.</param>
        /// <param name="content">The content.</param>
        /// <param name="temporalEvidence">The temporal evidence.</param>
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

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_dataUri = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);
            m_metaData = Asn1Utilities.ReadOptional(seq, ref pos, MetaData.GetOptional);
            m_content = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);
            m_temporalEvidence = Asn1Utilities.Read(seq, ref pos, Evidence.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the data uri.</summary>
        public virtual DerIA5String DataUri => m_dataUri;

        /// <summary>Gets the meta data.</summary>
        public MetaData MetaData => m_metaData;

        /// <summary>Gets the content.</summary>
        public Asn1OctetString Content => m_content;

        /// <summary>Gets the temporal evidence.</summary>
        public Evidence TemporalEvidence => m_temporalEvidence;

        /// <remarks>
        /// <code>
        /// TimeStampedData::= SEQUENCE {
        ///     version             INTEGER { v1(1) },
        ///     dataUri             IA5String OPTIONAL,
        ///     metaData            MetaData OPTIONAL,
        ///     content             OCTET STRING OPTIONAL,
        ///     temporalEvidence    Evidence
        /// }
        /// </code>
        /// </remarks>
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
