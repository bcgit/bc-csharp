using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <remarks>
    /// <code>
    /// KEMRecipientInfo ::= SEQUENCE {
    ///     version         CMSVersion,  -- always set to 0
    ///     rid             RecipientIdentifier,
    ///     kem             KEMAlgorithmIdentifier,
    ///     kemct           OCTET STRING,
    ///     kdf             KeyDerivationAlgorithmIdentifier,
    ///     kekLength       INTEGER(1..MAX),
    ///     ukm             [0] EXPLICIT UserKeyingMaterial OPTIONAL,
    ///     wrap            KeyEncryptionAlgorithmIdentifier,
    ///     encryptedKey    EncryptedKey }
    /// </code>
    /// </remarks>
    public sealed class KemRecipientInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KemRecipientInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KemRecipientInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KemRecipientInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static KemRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemRecipientInfo kemRecipientInfo)
                return kemRecipientInfo;
            return new KemRecipientInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="KemRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KemRecipientInfo"/>.</returns>
        public static KemRecipientInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemRecipientInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="KemRecipientInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KemRecipientInfo"/>.</returns>
        public static KemRecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemRecipientInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private static readonly DerInteger V1 = DerInteger.Zero;

        private readonly DerInteger m_cmsVersion;
        private readonly RecipientIdentifier m_rid;
        private readonly AlgorithmIdentifier m_kem;
        private readonly Asn1OctetString m_kemct;
        private readonly AlgorithmIdentifier m_kdf;
        private readonly DerInteger m_kekLength;
        private readonly Asn1OctetString m_ukm;
        private readonly AlgorithmIdentifier m_wrap;
        private readonly Asn1OctetString m_encryptedKey;

        /// <summary>Create a new <see cref="KemRecipientInfo"/>.</summary>
        /// <param name="rid">The rid.</param>
        /// <param name="kem">The kem.</param>
        /// <param name="kemct">The kemct.</param>
        /// <param name="kdf">The kdf.</param>
        /// <param name="kekLength">The kek length.</param>
        /// <param name="ukm">The ukm.</param>
        /// <param name="wrap">The wrap.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        public KemRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier kem, Asn1OctetString kemct,
            AlgorithmIdentifier kdf, DerInteger kekLength, Asn1OctetString ukm, AlgorithmIdentifier wrap,
            Asn1OctetString encryptedKey)
        {
            m_cmsVersion = V1;
            m_rid = rid ?? throw new ArgumentNullException(nameof(rid));
            m_kem = kem ?? throw new ArgumentNullException(nameof(kem));
            m_kemct = kemct ?? throw new ArgumentNullException(nameof(kemct));
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
            m_kekLength = ValidateKekLength(kekLength ?? throw new ArgumentNullException(nameof(kekLength)));
            m_ukm = ukm;
            m_wrap = wrap ?? throw new ArgumentNullException(nameof(wrap));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        private KemRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 8 || count > 9)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_cmsVersion = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_rid = Asn1Utilities.Read(seq, ref pos, RecipientIdentifier.GetInstance);
            m_kem = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_kemct = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_kdf = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            DerInteger kekLength = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_ukm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);
            m_wrap = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encryptedKey = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!m_cmsVersion.HasValue(0))
                throw new ArgumentException("Unsupported version (hex): " + m_cmsVersion.Value.ToString(16));

            m_kekLength = ValidateKekLength(kekLength);
        }

        /// <summary>Gets the recipient identifier.</summary>
        public RecipientIdentifier RecipientIdentifier => m_rid;

        /// <summary>Gets the kem.</summary>
        public AlgorithmIdentifier Kem => m_kem;

        /// <summary>Gets the kemct.</summary>
        public Asn1OctetString Kemct => m_kemct;

        /// <summary>Gets the kdf.</summary>
        public AlgorithmIdentifier Kdf => m_kdf;

        /// <summary>Gets the wrap.</summary>
        public AlgorithmIdentifier Wrap => m_wrap;

        /// <summary>Gets the ukm.</summary>
        public Asn1OctetString Ukm => m_ukm;

        /// <summary>Gets the encrypted key.</summary>
        public Asn1OctetString EncryptedKey => m_encryptedKey;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(9);
            v.Add(m_cmsVersion, m_rid, m_kem, m_kemct, m_kdf, m_kekLength);
            v.AddOptionalTagged(true, 0, m_ukm);
            v.Add(m_wrap, m_encryptedKey);
            return new DerSequence(v);
        }

        private static DerInteger ValidateKekLength(DerInteger kekLength)
        {
            if (!kekLength.TryGetIntValueExact(out int kekLengthValue))
                throw new ArgumentException("Invalid 'kekLength' (outside Int32 range)");

            if (kekLengthValue < 1 || kekLengthValue > 65535)
                throw new ArgumentException("Invalid 'kekLength': " + kekLengthValue);

            return kekLength;
        }
    }
}
