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

        private readonly DerInteger m_version;
        private readonly OriginatorIdentifierOrKey m_originator;
        private readonly Asn1OctetString m_ukm;
        private readonly AlgorithmIdentifier m_keyEncryptionAlgorithm;
        private readonly Asn1Sequence m_recipientEncryptedKeys;

        public KeyAgreeRecipientInfo(OriginatorIdentifierOrKey originator, Asn1OctetString ukm,
            AlgorithmIdentifier keyEncryptionAlgorithm, Asn1Sequence recipientEncryptedKeys)
        {
            m_version = DerInteger.Three;
            m_originator = originator ?? throw new ArgumentNullException(nameof(originator));
            m_ukm = ukm;
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_recipientEncryptedKeys = recipientEncryptedKeys ?? throw new ArgumentNullException(nameof(recipientEncryptedKeys));
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KeyAgreeRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_originator = Asn1Utilities.ReadContextTagged(seq, ref pos, 0, true, OriginatorIdentifierOrKey.GetTagged);
            m_ukm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1OctetString.GetTagged);
            m_keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_recipientEncryptedKeys = Asn1Sequence.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerInteger Version => m_version;

        public OriginatorIdentifierOrKey Originator => m_originator;

        public Asn1OctetString UserKeyingMaterial => m_ukm;

		public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        public Asn1Sequence RecipientEncryptedKeys => m_recipientEncryptedKeys;

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
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_version, new DerTaggedObject(true, 0, m_originator));
            v.AddOptionalTagged(true, 1, m_ukm);
			v.Add(m_keyEncryptionAlgorithm, m_recipientEncryptedKeys);
			return new DerSequence(v);
        }
    }
}
