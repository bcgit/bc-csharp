using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	public class MetaData
		: Asn1Encodable
	{
        public static MetaData GetInstance(object obj)
        {
			if (obj == null)
				return null;
			if (obj is MetaData metaData)
				return metaData;
            return new MetaData(Asn1Sequence.GetInstance(obj));
        }

        public static MetaData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new MetaData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        public static MetaData GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is MetaData metaData)
                return metaData;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new MetaData(asn1Sequence);

            return null;
        }

        private readonly DerBoolean m_hashProtected;
        private readonly DerUtf8String m_fileName;
        private readonly DerIA5String m_mediaType;
        private readonly Attributes m_otherMetaData;

        public MetaData(DerBoolean hashProtected, DerUtf8String fileName, DerIA5String mediaType,
            Attributes otherMetaData)
        {
            m_hashProtected = hashProtected ?? throw new ArgumentNullException(nameof(hashProtected));
            m_fileName = fileName;
            m_mediaType = mediaType;
            m_otherMetaData = otherMetaData;
        }

        private MetaData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashProtected = DerBoolean.GetInstance(seq[pos++]);
            m_fileName = Asn1Utilities.ReadOptional(seq, ref pos, DerUtf8String.GetOptional);
            m_mediaType = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);
            m_otherMetaData = Asn1Utilities.ReadOptional(seq, ref pos, Attributes.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual bool IsHashProtected => m_hashProtected.IsTrue;

        public virtual DerUtf8String FileName => m_fileName;

        public virtual DerIA5String MediaType => m_mediaType;

        public virtual Attributes OtherMetaData => m_otherMetaData;

        /**
		 * <pre>
		 * MetaData ::= SEQUENCE {
		 *   hashProtected        BOOLEAN,
		 *   fileName             UTF8String OPTIONAL,
		 *   mediaType            IA5String OPTIONAL,
		 *   otherMetaData        Attributes OPTIONAL
		 * }
		 * </pre>
		 * @return
		 */
        public override Asn1Object ToAsn1Object()
		{
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_hashProtected);
			v.AddOptional(m_fileName, m_mediaType, m_otherMetaData);
			return new DerSequence(v);
		}
	}
}
