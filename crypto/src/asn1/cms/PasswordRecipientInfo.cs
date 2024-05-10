using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class PasswordRecipientInfo
        : Asn1Encodable
    {
        public static PasswordRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PasswordRecipientInfo passwordRecipientInfo)
                return passwordRecipientInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new PasswordRecipientInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static PasswordRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PasswordRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger				version;
        private readonly AlgorithmIdentifier	keyDerivationAlgorithm;
        private readonly AlgorithmIdentifier	keyEncryptionAlgorithm;
        private readonly Asn1OctetString		encryptedKey;

		public PasswordRecipientInfo(
            AlgorithmIdentifier	keyEncryptionAlgorithm,
            Asn1OctetString		encryptedKey)
        {
            this.version = new DerInteger(0);
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            this.encryptedKey = encryptedKey;
        }

		public PasswordRecipientInfo(
			AlgorithmIdentifier	keyDerivationAlgorithm,
			AlgorithmIdentifier	keyEncryptionAlgorithm,
			Asn1OctetString		encryptedKey)
		{
			this.version = new DerInteger(0);
			this.keyDerivationAlgorithm = keyDerivationAlgorithm;
			this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
			this.encryptedKey = encryptedKey;
		}

        [Obsolete("Use 'GetInstance' instead")]
        public PasswordRecipientInfo(Asn1Sequence seq)
        {
            version = (DerInteger)seq[0];

			if (seq[1] is Asn1TaggedObject taggedObject)
            {
                keyDerivationAlgorithm = AlgorithmIdentifier.GetInstance(taggedObject, false);
                keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[2]);
                encryptedKey = (Asn1OctetString)seq[3];
            }
            else
            {
                keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
                encryptedKey = (Asn1OctetString)seq[2];
            }
        }

        public DerInteger Version
		{
			get { return version; }
		}

		public AlgorithmIdentifier KeyDerivationAlgorithm
		{
			get { return keyDerivationAlgorithm; }
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
         * PasswordRecipientInfo ::= Sequence {
         *   version CMSVersion,   -- Always set to 0
         *   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
         *                             OPTIONAL,
         *  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
         *  encryptedKey EncryptedKey }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(version);
            v.AddOptionalTagged(false, 0, keyDerivationAlgorithm);
			v.Add(keyEncryptionAlgorithm, encryptedKey);
			return new DerSequence(v);
        }
    }
}
