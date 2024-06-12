using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class KeyAgreeRecipientInfo
        : Asn1Encodable
    {
        public static KeyAgreeRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KeyAgreeRecipientInfo keyAgreeRecipientInfo)
                return keyAgreeRecipientInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeyAgreeRecipientInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KeyAgreeRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeyAgreeRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private DerInteger                  version;
        private OriginatorIdentifierOrKey   originator;
        private Asn1OctetString             ukm;
        private AlgorithmIdentifier         keyEncryptionAlgorithm;
        private Asn1Sequence                recipientEncryptedKeys;

		public KeyAgreeRecipientInfo(
            OriginatorIdentifierOrKey   originator,
            Asn1OctetString             ukm,
            AlgorithmIdentifier         keyEncryptionAlgorithm,
            Asn1Sequence                recipientEncryptedKeys)
        {
            this.version = DerInteger.Three;
            this.originator = originator;
            this.ukm = ukm;
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            this.recipientEncryptedKeys = recipientEncryptedKeys;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KeyAgreeRecipientInfo(Asn1Sequence seq)
        {
            int index = 0;

            version = (DerInteger) seq[index++];
            originator = OriginatorIdentifierOrKey.GetInstance((Asn1TaggedObject)seq[index++], true);

			if (seq[index] is Asn1TaggedObject taggedObject)
            {
                ukm = Asn1OctetString.GetInstance(taggedObject, true);
                ++index;
            }

			keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[index++]);

			recipientEncryptedKeys = (Asn1Sequence)seq[index++];
        }

        public DerInteger Version
		{
			get { return version; }
		}

		public OriginatorIdentifierOrKey Originator
		{
			get { return originator; }
		}

		public Asn1OctetString UserKeyingMaterial
		{
			get { return ukm; }
		}

		public AlgorithmIdentifier KeyEncryptionAlgorithm
		{
			get { return keyEncryptionAlgorithm; }
		}

		public Asn1Sequence RecipientEncryptedKeys
		{
			get { return recipientEncryptedKeys; }
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * KeyAgreeRecipientInfo ::= Sequence {
         *     version CMSVersion,  -- always set to 3
         *     originator [0] EXPLICIT OriginatorIdentifierOrKey,
         *     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
         *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
         *     recipientEncryptedKeys RecipientEncryptedKeys
         * }
		 *
		 * UserKeyingMaterial ::= OCTET STRING
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(version, new DerTaggedObject(true, 0, originator));
            v.AddOptionalTagged(true, 1, ukm);
			v.Add(keyEncryptionAlgorithm, recipientEncryptedKeys);
			return new DerSequence(v);
        }
    }
}
