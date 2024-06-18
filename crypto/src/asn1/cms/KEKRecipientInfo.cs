using System;

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
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekRecipientInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KekRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly KekIdentifier m_kekID;
        private readonly AlgorithmIdentifier m_keyEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedKey;

        public KekRecipientInfo(KekIdentifier kekID, AlgorithmIdentifier keyEncryptionAlgorithm,
            Asn1OctetString encryptedKey)
        {
            m_version = DerInteger.Four;
            m_kekID = kekID ?? throw new ArgumentNullException(nameof(kekID));
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KekRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[0]);
            m_kekID = KekIdentifier.GetInstance(seq[1]);
            m_keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[2]);
            m_encryptedKey = Asn1OctetString.GetInstance(seq[3]);
        }

        public DerInteger Version => m_version;

        public KekIdentifier KekID => m_kekID;

		public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        public Asn1OctetString EncryptedKey => m_encryptedKey;

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
        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_version, m_kekID, m_keyEncryptionAlgorithm, m_encryptedKey);
    }
}
