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

        public static RecipientEncryptedKey GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new RecipientEncryptedKey(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly KeyAgreeRecipientIdentifier identifier;
		private readonly Asn1OctetString encryptedKey;

		private RecipientEncryptedKey(
			Asn1Sequence seq)
		{
			identifier = KeyAgreeRecipientIdentifier.GetInstance(seq[0]);
			encryptedKey = (Asn1OctetString) seq[1];
		}

        public RecipientEncryptedKey(
			KeyAgreeRecipientIdentifier	id,
			Asn1OctetString				encryptedKey)
		{
			this.identifier = id;
			this.encryptedKey = encryptedKey;
		}

		public KeyAgreeRecipientIdentifier Identifier
		{
			get { return identifier; }
		}

		public Asn1OctetString EncryptedKey
		{
			get { return encryptedKey; }
		}

		/** 
		 * Produce an object suitable for an Asn1OutputStream.
		 * <pre>
		 * RecipientEncryptedKey ::= SEQUENCE {
		 *     rid KeyAgreeRecipientIdentifier,
		 *     encryptedKey EncryptedKey
		 * }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(identifier, encryptedKey);
		}
	}
}
