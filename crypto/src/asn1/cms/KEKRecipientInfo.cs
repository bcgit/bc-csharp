using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>
    /// The KEKRecipientInfo structure of RFC 5652, for recipients using a previously distributed key encryption key.
    /// </summary>
    public class KekRecipientInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KekRecipientInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KekRecipientInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KekRecipientInfo"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="KekRecipientInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KekRecipientInfo"/>.</returns>
        public static KekRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="KekRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KekRecipientInfo"/>.</returns>
        public static KekRecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekRecipientInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly KekIdentifier m_kekID;
        private readonly AlgorithmIdentifier m_keyEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedKey;

        /// <summary>Create a new <see cref="KekRecipientInfo"/>.</summary>
        /// <param name="kekID">The kek ID.</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        public KekRecipientInfo(KekIdentifier kekID, AlgorithmIdentifier keyEncryptionAlgorithm,
            Asn1OctetString encryptedKey)
        {
            m_version = DerInteger.Four;
            m_kekID = kekID ?? throw new ArgumentNullException(nameof(kekID));
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        /// <summary>Create a new <see cref="KekRecipientInfo"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public KekRecipientInfo(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_kekID = Asn1Utilities.Read(seq, ref pos, KekIdentifier.GetInstance);
            m_keyEncryptionAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encryptedKey = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the kek ID.</summary>
        public KekIdentifier KekID => m_kekID;

        /// <summary>Gets the key encryption algorithm.</summary>
        public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        /// <summary>Gets the encrypted key.</summary>
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
