using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
     *   KEMRecipientInfo ::= SEQUENCE {
     *     version CMSVersion,  -- always set to 0
     *     rid RecipientIdentifier,
     *     kem KEMAlgorithmIdentifier,
     *     kemct OCTET STRING,
     *     kdf KeyDerivationAlgorithmIdentifier,
     *     kekLength INTEGER (1..MAX),
     *     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
     *     wrap KeyEncryptionAlgorithmIdentifier,
     *     encryptedKey EncryptedKey }
     */
    public sealed class KemRecipientInfo
        : Asn1Encodable
    {
        public static KemRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemRecipientInfo kemRecipientInfo)
                return kemRecipientInfo;
            return new KemRecipientInfo(Asn1Sequence.GetInstance(obj));
        }

        public static KemRecipientInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemRecipientInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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

        public KemRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier kem, Asn1OctetString kemct,
            AlgorithmIdentifier kdf, DerInteger kekLength, Asn1OctetString ukm, AlgorithmIdentifier wrap,
            Asn1OctetString encryptedKey)
        {
            m_cmsVersion = V1;
            m_rid = rid ?? throw new ArgumentNullException(nameof(rid));
            m_kem = kem ?? throw new ArgumentNullException(nameof(kem));
            m_kemct = kemct ?? throw new ArgumentNullException(nameof(kemct));
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
            m_kekLength = kekLength ?? throw new ArgumentNullException(nameof(kekLength));
            m_ukm = ukm;
            m_wrap = wrap ?? throw new ArgumentNullException(nameof(wrap));
            m_encryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

        private KemRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 8 || count > 9)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_cmsVersion = DerInteger.GetInstance(seq[pos++]);
            m_rid = RecipientIdentifier.GetInstance(seq[pos++]);
            m_kem = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_kemct = Asn1OctetString.GetInstance(seq[pos++]);
            m_kdf = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_kekLength = DerInteger.GetInstance(seq[pos++]);
            m_ukm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);
            m_wrap = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_encryptedKey = Asn1OctetString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!m_cmsVersion.HasValue(0))
                throw new ArgumentException("Unsupported version (hex): " + m_cmsVersion.Value.ToString(16));
        }

        public RecipientIdentifier RecipientIdentifier => m_rid;

        public AlgorithmIdentifier Kem => m_kem;

        public Asn1OctetString Kemct => m_kemct;

        public AlgorithmIdentifier Kdf => m_kdf;

        public AlgorithmIdentifier Wrap => m_wrap;

        public Asn1OctetString Ukm => m_ukm;

        public Asn1OctetString EncryptedKey => m_encryptedKey;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(9);
            v.Add(m_cmsVersion, m_rid, m_kem, m_kemct, m_kdf, m_kekLength);
            v.AddOptionalTagged(true, 0, m_ukm);
            v.Add(m_wrap, m_encryptedKey);
            return new DerSequence(v);
        }
    }
}
