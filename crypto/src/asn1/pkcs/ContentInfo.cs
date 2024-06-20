using System;

namespace Org.BouncyCastle.Asn1.Pkcs
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

        public static ContentInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ContentInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerObjectIdentifier m_contentType;
        private readonly Asn1Encodable m_content;

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
        }

        public ContentInfo(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_content = content;
        }

        public DerObjectIdentifier ContentType => m_contentType;

        public Asn1Encodable Content => m_content;

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
            return m_content == null
                ?  new BerSequence(m_contentType)
                :  new BerSequence(m_contentType, new BerTaggedObject(0, m_content));
        }
    }
}
