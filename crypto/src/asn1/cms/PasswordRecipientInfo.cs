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

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_keyDerivationAlgorithm;
        private readonly AlgorithmIdentifier m_keyEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedKey;

        public PasswordRecipientInfo(AlgorithmIdentifier keyEncryptionAlgorithm, Asn1OctetString encryptedKey)
            : this(keyDerivationAlgorithm: null, keyEncryptionAlgorithm, encryptedKey)
        {
        }

		public PasswordRecipientInfo(AlgorithmIdentifier keyDerivationAlgorithm,
            AlgorithmIdentifier keyEncryptionAlgorithm, Asn1OctetString encryptedKey)
		{
            m_version = DerInteger.Zero;
            m_keyDerivationAlgorithm = keyDerivationAlgorithm;
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
		}

        [Obsolete("Use 'GetInstance' instead")]
        public PasswordRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_keyDerivationAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false,
                AlgorithmIdentifier.GetTagged);
            m_keyEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_encryptedKey = Asn1OctetString.GetInstance(seq[pos++]);
        }

        public DerInteger Version => m_version;

        public AlgorithmIdentifier KeyDerivationAlgorithm => m_keyDerivationAlgorithm;

        public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        public Asn1OctetString EncryptedKey => m_encryptedKey;

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
            if (m_keyDerivationAlgorithm == null)
                return new DerSequence(m_version, m_keyEncryptionAlgorithm, m_encryptedKey);

            return new DerSequence(m_version, new DerTaggedObject(false, 0, m_keyDerivationAlgorithm),
                m_keyEncryptionAlgorithm, m_encryptedKey);
        }
    }
}
