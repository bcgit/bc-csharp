using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class EncryptedContentInfo
        : Asn1Encodable
    {
        public static EncryptedContentInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedContentInfo encryptedContentInfo)
                return encryptedContentInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new EncryptedContentInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static EncryptedContentInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new EncryptedContentInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static EncryptedContentInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new EncryptedContentInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private DerObjectIdentifier m_contentType;
        private AlgorithmIdentifier m_contentEncryptionAlgorithm;
        private Asn1OctetString m_encryptedContent;

        public EncryptedContentInfo(DerObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm,
            Asn1OctetString encryptedContent)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            m_contentEncryptionAlgorithm = contentEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(contentEncryptionAlgorithm));
            m_encryptedContent = encryptedContent;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public EncryptedContentInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_contentType = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_contentEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_encryptedContent = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerObjectIdentifier ContentType => m_contentType;

        public AlgorithmIdentifier ContentEncryptionAlgorithm => m_contentEncryptionAlgorithm;

        public Asn1OctetString EncryptedContent => m_encryptedContent;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * EncryptedContentInfo ::= Sequence {
         *     contentType ContentType,
         *     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
         *     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_contentType, m_contentEncryptionAlgorithm);

			if (m_encryptedContent != null)
            {
                v.Add(new BerTaggedObject(false, 0, m_encryptedContent));
            }

			return new BerSequence(v);
        }
    }
}
