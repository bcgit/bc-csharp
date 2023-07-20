using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class KekRecipientInfo
        : Asn1Encodable
    {
        public static KekRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KekRecipientInfo kekRecipientInfo)
                return kekRecipientInfo;
            return new KekRecipientInfo(Asn1Sequence.GetInstance(obj));
        }

        public static KekRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new KekRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private DerInteger			version;
        private KekIdentifier       kekID;
        private AlgorithmIdentifier keyEncryptionAlgorithm;
        private Asn1OctetString     encryptedKey;

		public KekRecipientInfo(
            KekIdentifier       kekID,
            AlgorithmIdentifier keyEncryptionAlgorithm,
            Asn1OctetString     encryptedKey)
        {
            this.version = new DerInteger(4);
            this.kekID = kekID;
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            this.encryptedKey = encryptedKey;
        }

		public KekRecipientInfo(
            Asn1Sequence seq)
        {
            version = (DerInteger) seq[0];
            kekID = KekIdentifier.GetInstance(seq[1]);
            keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[2]);
            encryptedKey = (Asn1OctetString) seq[3];
        }

        public DerInteger Version
		{
			get { return version; }
		}

		public KekIdentifier KekID
		{
			get { return kekID; }
		}

		public AlgorithmIdentifier KeyEncryptionAlgorithm
		{
			get { return keyEncryptionAlgorithm; }
		}

		public Asn1OctetString EncryptedKey
		{
			get { return encryptedKey; }
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * KekRecipientInfo ::= Sequence {
         *     version CMSVersion,  -- always set to 4
         *     kekID KekIdentifier,
         *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
         *     encryptedKey EncryptedKey
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(version, kekID, keyEncryptionAlgorithm, encryptedKey);
        }
    }
}
