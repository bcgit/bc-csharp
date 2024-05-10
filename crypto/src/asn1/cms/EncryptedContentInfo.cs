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

        private DerObjectIdentifier	contentType;
        private AlgorithmIdentifier	contentEncryptionAlgorithm;
        private Asn1OctetString		encryptedContent;

		public EncryptedContentInfo(
            DerObjectIdentifier	contentType,
            AlgorithmIdentifier	contentEncryptionAlgorithm,
            Asn1OctetString		encryptedContent)
        {
            this.contentType = contentType;
            this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
            this.encryptedContent = encryptedContent;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public EncryptedContentInfo(
            Asn1Sequence seq)
        {
            contentType = (DerObjectIdentifier) seq[0];
            contentEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);

			if (seq.Count > 2)
            {
                encryptedContent = Asn1OctetString.GetInstance(
					(Asn1TaggedObject) seq[2], false);
            }
        }

        public DerObjectIdentifier ContentType
        {
            get { return contentType; }
        }

		public AlgorithmIdentifier ContentEncryptionAlgorithm
        {
			get { return contentEncryptionAlgorithm; }
        }

		public Asn1OctetString EncryptedContent
        {
			get { return encryptedContent; }
        }

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
            Asn1EncodableVector v = new Asn1EncodableVector(
				contentType, contentEncryptionAlgorithm);

			if (encryptedContent != null)
            {
                v.Add(new BerTaggedObject(false, 0, encryptedContent));
            }

			return new BerSequence(v);
        }
    }
}
