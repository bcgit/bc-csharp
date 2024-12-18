using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class ContentInfo
        : Asn1Encodable
    {
        public static ContentInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ContentInfo contentInfo)
                return contentInfo;
            return new ContentInfo(Asn1Sequence.GetInstance(obj));
        }

        public static ContentInfo GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new ContentInfo(Asn1Sequence.GetInstance(obj, isExplicit));

        public static ContentInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_contentType;
        private readonly Asn1Encodable m_content;

        private readonly bool m_isDefiniteLength;

        private ContentInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_contentType = DerObjectIdentifier.GetInstance(seq[0]);

            if (seq.Count > 1)
            {
                m_content = Asn1TaggedObject.GetInstance(seq[1], Asn1Tags.ContextSpecific, 0).GetExplicitBaseObject();
            }
            else
            {
                m_content = null;
            }

            m_isDefiniteLength = IsDLSequence(seq);
        }

        public ContentInfo(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_content = content;

            m_isDefiniteLength = IsDLContent(content);
        }

        public DerObjectIdentifier ContentType => m_contentType;

        public Asn1Encodable Content => m_content;

        internal bool IsDefiniteLength => m_isDefiniteLength;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ContentInfo ::= Sequence {
         *          contentType ContentType,
         *          content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_isDefiniteLength)
            {
                return m_content == null
                    ? new DLSequence(m_contentType)
                    : new DLSequence(m_contentType, new DLTaggedObject(0, m_content));
            }

            return m_content == null
                ?  new BerSequence(m_contentType)
                :  new BerSequence(m_contentType, new BerTaggedObject(0, m_content));
        }

        private static bool IsDLContent(Asn1Encodable content)
        {
            if (content == null)
                return true;

            var asn1Object = content.ToAsn1Object();

            return IsDLOctetString(asn1Object)
                || IsDLSequence(asn1Object);
        }

        private static bool IsDLOctetString(Asn1Object asn1Object) =>
            asn1Object.GetType().IsAssignableFrom(typeof(DerOctetString));

        private static bool IsDLSequence(Asn1Object asn1Object) =>
            asn1Object.GetType().IsAssignableFrom(typeof(DLSequence));
    }
}
