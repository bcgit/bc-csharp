using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The KeyTransRecipientInfo structure of RFC 5652, for recipients using key transport.</summary>
    public class KeyTransRecipientInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KeyTransRecipientInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KeyTransRecipientInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KeyTransRecipientInfo"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="KeyTransRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeyTransRecipientInfo"/>.</returns>
        public static KeyTransRecipientInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeyTransRecipientInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="KeyTransRecipientInfo"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="KeyTransRecipientInfo"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="KeyTransRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeyTransRecipientInfo"/>.</returns>
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

        /// <summary>Create a new <see cref="KeyTransRecipientInfo"/>.</summary>
        /// <param name="rid">The rid.</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        public KeyTransRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm,
            Asn1OctetString encryptedKey)
        {
            m_rid = rid ?? throw new ArgumentNullException(nameof(rid));
            m_keyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
            m_version = rid.IsTagged ? DerInteger.Two : DerInteger.Zero;
        }

        /// <summary>Create a new <see cref="KeyTransRecipientInfo"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public KeyTransRecipientInfo(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_rid = Asn1Utilities.Read(seq, ref pos, RecipientIdentifier.GetInstance);
            m_keyEncryptionAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encryptedKey = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        public RecipientIdentifier RecipientIdentifier => m_rid;

        /// <summary>Gets the key encryption algorithm.</summary>
        public AlgorithmIdentifier KeyEncryptionAlgorithm => m_keyEncryptionAlgorithm;

        /// <summary>Gets the encrypted key.</summary>
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
