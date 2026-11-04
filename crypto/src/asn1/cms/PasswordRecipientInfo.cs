using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The PasswordRecipientInfo structure of RFC 5652, for recipients using a password.</summary>
    public class PasswordRecipientInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PasswordRecipientInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PasswordRecipientInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PasswordRecipientInfo"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="PasswordRecipientInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PasswordRecipientInfo"/>.</returns>
        public static PasswordRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PasswordRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="PasswordRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PasswordRecipientInfo"/>.</returns>
        public static PasswordRecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PasswordRecipientInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_keyDerivationAlgorithm;
        private readonly AlgorithmIdentifier m_keyEncryptionAlgorithm;
        private readonly Asn1OctetString m_encryptedKey;

        /// <summary>Create a new <see cref="PasswordRecipientInfo"/>.</summary>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        public PasswordRecipientInfo(AlgorithmIdentifier keyEncryptionAlgorithm, Asn1OctetString encryptedKey)
            : this(keyDerivationAlgorithm: null, keyEncryptionAlgorithm, encryptedKey)
        {
        }

        /// <summary>Create a new <see cref="PasswordRecipientInfo"/>.</summary>
        /// <param name="keyDerivationAlgorithm">The key derivation algorithm.</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        public PasswordRecipientInfo(AlgorithmIdentifier keyDerivationAlgorithm,
            AlgorithmIdentifier keyEncryptionAlgorithm, Asn1OctetString encryptedKey)
        {
            m_version = DerInteger.Zero;
            m_keyDerivationAlgorithm = keyDerivationAlgorithm;
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        /// <summary>Create a new <see cref="PasswordRecipientInfo"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public PasswordRecipientInfo(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_keyDerivationAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false,
                AlgorithmIdentifier.GetTagged);
            m_keyEncryptionAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encryptedKey = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the key derivation algorithm.</summary>
        public AlgorithmIdentifier KeyDerivationAlgorithm => m_keyDerivationAlgorithm;

        /// <summary>Gets the key encryption algorithm.</summary>
        public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        /// <summary>Gets the encrypted key.</summary>
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
