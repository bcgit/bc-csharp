using System;

using Org.BouncyCastle.Asn1.X509;

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

        public static KeyTransRecipientInfo GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is KeyTransRecipientInfo keyTransRecipientInfo)
                return keyTransRecipientInfo;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                return new KeyTransRecipientInfo(asn1Sequence);
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return null;
        }

        public static KeyTransRecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeyTransRecipientInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly RecipientIdentifier m_rid;
        private readonly AlgorithmIdentifier m_keyEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedKey;

        public KeyTransRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm,
            Asn1OctetString encryptedKey)
        {
            m_rid = rid ?? throw new ArgumentNullException(nameof(rid));
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
            m_version = rid.IsTagged ? DerInteger.Two : DerInteger.Zero;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KeyTransRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[0]);
            m_rid = RecipientIdentifier.GetInstance(seq[1]);
            m_keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[2]);
            m_encryptedKey = Asn1OctetString.GetInstance(seq[3]);
        }

        public DerInteger Version => m_version;

        public RecipientIdentifier RecipientIdentifier => m_rid;

        public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        public Asn1OctetString EncryptedKey => m_encryptedKey;

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
        public override Asn1Object ToAsn1Object() =>
			new DerSequence(m_version, m_rid, m_keyEncryptionAlgorithm, m_encryptedKey);
    }
}
