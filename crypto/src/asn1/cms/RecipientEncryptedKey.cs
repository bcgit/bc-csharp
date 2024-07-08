using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class RecipientEncryptedKey
		: Asn1Encodable
	{
        public static RecipientEncryptedKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RecipientEncryptedKey recipientEncryptedKey)
                return recipientEncryptedKey;
            return new RecipientEncryptedKey(Asn1Sequence.GetInstance(obj));
        }

        public static RecipientEncryptedKey GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new RecipientEncryptedKey(Asn1Sequence.GetInstance(obj, isExplicit));

        public static RecipientEncryptedKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RecipientEncryptedKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly KeyAgreeRecipientIdentifier m_identifier;
		private readonly Asn1OctetString m_encryptedKey;

		private RecipientEncryptedKey(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_identifier = KeyAgreeRecipientIdentifier.GetInstance(seq[0]);
			m_encryptedKey = Asn1OctetString.GetInstance(seq[1]);
		}

        public RecipientEncryptedKey(KeyAgreeRecipientIdentifier id, Asn1OctetString encryptedKey)
        {
            m_identifier = id ?? throw new ArgumentNullException(nameof(id));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        public KeyAgreeRecipientIdentifier Identifier => m_identifier;

		public Asn1OctetString EncryptedKey => m_encryptedKey;

		/** 
		 * Produce an object suitable for an Asn1OutputStream.
		 * <pre>
		 * RecipientEncryptedKey ::= SEQUENCE {
		 *     rid KeyAgreeRecipientIdentifier,
		 *     encryptedKey EncryptedKey
		 * }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object() => new DerSequence(m_identifier, m_encryptedKey);
	}
}
