using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class KeyTransRecipientInfo
        : Asn1Encodable
    {
        public static KeyTransRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KeyTransRecipientInfo keyTransRecipientInfo)
                return keyTransRecipientInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeyTransRecipientInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KeyTransRecipientInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeyTransRecipientInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private DerInteger          version;
        private RecipientIdentifier rid;
        private AlgorithmIdentifier keyEncryptionAlgorithm;
        private Asn1OctetString     encryptedKey;

		public KeyTransRecipientInfo(
            RecipientIdentifier rid,
            AlgorithmIdentifier keyEncryptionAlgorithm,
            Asn1OctetString     encryptedKey)
        {
            if (rid.ToAsn1Object() is Asn1TaggedObject)
            {
                this.version = DerInteger.Two;
            }
            else
            {
                this.version = DerInteger.Zero;
            }

			this.rid = rid;
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            this.encryptedKey = encryptedKey;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KeyTransRecipientInfo(
            Asn1Sequence seq)
        {
            this.version = (DerInteger) seq[0];
            this.rid = RecipientIdentifier.GetInstance(seq[1]);
            this.keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[2]);
            this.encryptedKey = (Asn1OctetString) seq[3];
        }

		public DerInteger Version
		{
			get { return version; }
		}

		public RecipientIdentifier RecipientIdentifier
		{
			get { return rid; }
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
         * KeyTransRecipientInfo ::= Sequence {
         *     version CMSVersion,  -- always set to 0 or 2
         *     rid RecipientIdentifier,
         *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
         *     encryptedKey EncryptedKey
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(version, rid, keyEncryptionAlgorithm, encryptedKey);
        }
    }
}
