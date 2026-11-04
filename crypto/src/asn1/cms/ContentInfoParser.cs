using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
    * Produce an object suitable for an Asn1OutputStream.
    * <pre>
    * ContentInfo ::= SEQUENCE {
    *          contentType ContentType,
    *          content
    *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
    * </pre>
    */
    public class ContentInfoParser
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly Asn1TaggedObjectParser m_content;

        /// <summary>Create a new <see cref="ContentInfoParser"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        public ContentInfoParser(Asn1SequenceParser seq)
        {
            m_contentType = (DerObjectIdentifier)seq.ReadObject();
            m_content = (Asn1TaggedObjectParser)seq.ReadObject();
        }

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_contentType;

        /// <summary>Get the content, parsed according to the tag.</summary>
        /// <param name="tag">The tag of the content.</param>
        /// <returns>The content, or null if there is none.</returns>
        public IAsn1Convertible GetContent(int tag)
        {
            if (null == m_content)
                return null;

            // TODO[cms] Ideally we could enforce the claimed tag
            //return Asn1Utilities.ParseContextBaseUniversal(content, 0, true, tag);
            return Asn1Utilities.ParseExplicitContextBaseObject(m_content, 0);
        }
    }
}
