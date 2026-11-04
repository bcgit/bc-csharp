using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The ContentInfo structure of RFC 5652: a content type and the content.</summary>
    public class ContentInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ContentInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ContentInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ContentInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ContentInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ContentInfo contentInfo)
                return contentInfo;
            return new ContentInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ContentInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ContentInfo"/>.</returns>
        public static ContentInfo GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new ContentInfo(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="ContentInfo"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="ContentInfo"/>, or null if <paramref name="element"/> is null.</returns>
        public static ContentInfo GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ContentInfo contentInfo)
                return contentInfo;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new ContentInfo(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="ContentInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ContentInfo"/>.</returns>
        public static ContentInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_contentType;
        private readonly Asn1Encodable m_content;

        private readonly bool m_isDefiniteLength;

        private ContentInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_contentType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_content = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true,
                (taggedObject, declaredExplicit) => taggedObject.GetExplicitBaseObject());

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_isDefiniteLength = IsDLSequence(seq);
        }

        /// <summary>Create a new <see cref="ContentInfo"/>.</summary>
        /// <param name="contentType">The content type.</param>
        /// <param name="content">The content.</param>
        public ContentInfo(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_content = content;

            m_isDefiniteLength = IsDLContent(content);
        }

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_contentType;

        /// <summary>Gets the content.</summary>
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
