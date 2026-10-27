using System;

namespace Org.BouncyCastle.Asn1.Ess
{
    /// <summary>The ContentHints structure of RFC 2634.</summary>
    public class ContentHints
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ContentHints"/> from the given object.</summary>
        /// <param name="o">An <see cref="ContentHints"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="ContentHints"/>, or null if <paramref name="o"/> is null.</returns>
        public static ContentHints GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is ContentHints contentHints)
                return contentHints;
            return new ContentHints(Asn1Sequence.GetInstance(o));
        }

        /// <summary>Return an <see cref="ContentHints"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ContentHints"/>.</returns>
        public static ContentHints GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentHints(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ContentHints"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ContentHints"/>.</returns>
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
            m_contentType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="ContentHints"/>.</summary>
        /// <param name="contentType">The content type.</param>
        public ContentHints(DerObjectIdentifier contentType)
            : this(contentType, null)
        {
        }

        /// <summary>Create a new <see cref="ContentHints"/>.</summary>
        /// <param name="contentType">The content type.</param>
        /// <param name="contentDescription">The content description.</param>
        public ContentHints(DerObjectIdentifier contentType, DerUtf8String contentDescription)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_contentDescription = contentDescription;
        }

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_contentType;

        /// <summary>Gets the content description.</summary>
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
