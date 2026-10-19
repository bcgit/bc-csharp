using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
    * <pre>
    * EncryptedContentInfo ::= SEQUENCE {
    *     contentType ContentType,
    *     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    *     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
    * }
    * </pre>
    */
    public class EncryptedContentInfoParser
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly AlgorithmIdentifier m_contentEncryptionAlgorithm;
        private readonly Asn1TaggedObjectParser m_encryptedContent;

        /// <summary>Create a new <see cref="EncryptedContentInfoParser"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        public EncryptedContentInfoParser(Asn1SequenceParser seq)
        {
            m_contentType = (DerObjectIdentifier)seq.ReadObject();
            m_contentEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq.ReadObject().ToAsn1Object());
            m_encryptedContent = (Asn1TaggedObjectParser)seq.ReadObject();
        }

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_contentType;

        /// <summary>Gets the content encryption algorithm.</summary>
        public AlgorithmIdentifier ContentEncryptionAlgorithm => m_contentEncryptionAlgorithm;

        public IAsn1Convertible GetEncryptedContent(int tag)
        {
            return Asn1Utilities.ParseContextBaseUniversal(m_encryptedContent, 0, false, tag);
        }
    }
}
