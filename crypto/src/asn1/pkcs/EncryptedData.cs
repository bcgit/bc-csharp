using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * The EncryptedData object.
     * <pre>
     *      EncryptedData ::= Sequence {
     *           version Version,
     *           encryptedContentInfo EncryptedContentInfo
     *      }
     *
     *
     *      EncryptedContentInfo ::= Sequence {
     *          contentType ContentType,
     *          contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
     *          encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
     *    }
     *
     *    EncryptedContent ::= OCTET STRING
     * </pre>
     */
    public class EncryptedData
        : Asn1Encodable
    {
        private readonly Asn1Sequence m_data;
        //        private readonly DerObjectIdentifier bagId;
        //        private readonly Asn1Object bagValue;

        public static EncryptedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedData encryptedData)
                return encryptedData;
            return new EncryptedData(Asn1Sequence.GetInstance(obj));
        }

        public static EncryptedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static EncryptedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private EncryptedData(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            DerInteger version = DerInteger.GetInstance(seq[0]);
            if (!version.HasValue(0))
                throw new ArgumentException("sequence not version 0");

            m_data = Asn1Sequence.GetInstance(seq[1]);
        }

        public EncryptedData(DerObjectIdentifier contentType, AlgorithmIdentifier encryptionAlgorithm,
            Asn1Encodable content)
        {
            m_data = new BerSequence(contentType, encryptionAlgorithm, new BerTaggedObject(false, 0, content));
        }

        public DerObjectIdentifier ContentType => DerObjectIdentifier.GetInstance(m_data[0]);

		public AlgorithmIdentifier EncryptionAlgorithm => AlgorithmIdentifier.GetInstance(m_data[1]);

		public Asn1OctetString Content
        {
			get
			{
                if (m_data.Count != 3)
                    return null;

                Asn1TaggedObject tagged = Asn1TaggedObject.GetInstance(m_data[2], Asn1Tags.ContextSpecific, 0);

				return Asn1OctetString.GetInstance(tagged, declaredExplicit: false);
			}
        }

		public override Asn1Object ToAsn1Object() => new BerSequence(DerInteger.Zero, m_data);
    }
}
