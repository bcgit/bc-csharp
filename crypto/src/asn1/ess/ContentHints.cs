using System;

namespace Org.BouncyCastle.Asn1.Ess
{
    public class ContentHints
		: Asn1Encodable
	{
        public static ContentHints GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is ContentHints contentHints)
                return contentHints;
            return new ContentHints(Asn1Sequence.GetInstance(o));
        }

        public static ContentHints GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentHints(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ContentHints GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentHints(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerUtf8String m_contentDescription;
        private readonly DerObjectIdentifier m_contentType;

        private ContentHints(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_contentDescription = Asn1Utilities.ReadOptional(seq, ref pos, DerUtf8String.GetOptional);
            m_contentType = DerObjectIdentifier.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public ContentHints(DerObjectIdentifier contentType)
            : this(contentType, null)
        {
        }

        public ContentHints(DerObjectIdentifier contentType, DerUtf8String contentDescription)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_contentDescription = contentDescription;
        }

        public DerObjectIdentifier ContentType => m_contentType;

		public DerUtf8String ContentDescription => m_contentDescription;

		/**
		 * <pre>
		 * ContentHints ::= SEQUENCE {
		 *   contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
		 *   contentType ContentType }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_contentDescription == null
				?  new DerSequence(m_contentType)
                :  new DerSequence(m_contentDescription, m_contentType);
		}
	}
}
