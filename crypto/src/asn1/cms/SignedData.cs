using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
     * a signed data object.
     */
    public class SignedData
        : Asn1Encodable
    {
        public static SignedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignedData signedData)
                return signedData;
            return new SignedData(Asn1Sequence.GetInstance(obj));
        }

        public static SignedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SignedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Asn1Set m_digestAlgorithms;
        private readonly ContentInfo m_contentInfo;
        private readonly Asn1Set m_certificates;
        private readonly Asn1Set m_crls;
        private readonly Asn1Set m_signerInfos;

        private readonly bool m_certsBer;
        private readonly bool m_crlsBer;
        private readonly bool m_digsBer;
        private readonly bool m_sigsBer;

        public SignedData(Asn1Set digestAlgorithms, ContentInfo contentInfo, Asn1Set certificates, Asn1Set crls,
            Asn1Set signerInfos)
        {
            m_digestAlgorithms = digestAlgorithms ?? throw new ArgumentNullException(nameof(digestAlgorithms));
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_certificates = certificates;
            m_crls = crls;
            m_signerInfos = signerInfos ?? throw new ArgumentNullException(nameof(signerInfos));
            m_version = CalculateVersionField(contentInfo.ContentType, certificates, crls, signerInfos);

            m_certsBer = m_certificates is BerSet;
            m_crlsBer = m_crls is BerSet;
            m_digsBer = m_digestAlgorithms is BerSet;
            m_sigsBer = m_signerInfos is BerSet;
        }

        private SignedData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_digestAlgorithms = Asn1Set.GetInstance(seq[pos++]);
            m_contentInfo = ContentInfo.GetInstance(seq[pos++]);
            m_certificates = ReadOptionalTaggedSet(seq, ref pos, 0, out m_certsBer);
            m_crls = ReadOptionalTaggedSet(seq, ref pos, 1, out m_crlsBer);
            m_signerInfos = Asn1Set.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_digsBer = m_digestAlgorithms is BerSet;
            m_sigsBer = m_signerInfos is BerSet;
        }

        public DerInteger Version => m_version;

        public Asn1Set DigestAlgorithms => m_digestAlgorithms;

        public ContentInfo EncapContentInfo => m_contentInfo;

        public Asn1Set Certificates => m_certificates;

        public Asn1Set CRLs => m_crls;

        public Asn1Set SignerInfos => m_signerInfos;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SignedData ::= Sequence {
         *     version CMSVersion,
         *     digestAlgorithms DigestAlgorithmIdentifiers,
         *     encapContentInfo EncapsulatedContentInfo,
         *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
         *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
         *     signerInfos SignerInfos
         *   }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);
            v.Add(m_version, m_digestAlgorithms, m_contentInfo);

            if (m_certificates != null)
            {
                if (m_certsBer)
                {
                    v.Add(new BerTaggedObject(false, 0, m_certificates));
                }
                else
                {
                    v.Add(new DerTaggedObject(false, 0, m_certificates));
                }
            }

            if (m_crls != null)
            {
                if (m_crlsBer)
                {
                    v.Add(new BerTaggedObject(false, 1, m_crls));
                }
                else
                {
                    v.Add(new DerTaggedObject(false, 1, m_crls));
                }
            }

            v.Add(m_signerInfos);

            if (!m_contentInfo.IsDefiniteLength || m_certsBer || m_crlsBer || m_digsBer || m_sigsBer)
                return new BerSequence(v);

            return new DLSequence(v);
        }

        private static DerInteger CalculateVersionField(DerObjectIdentifier contentOid, Asn1Set certs, Asn1Set crls,
            Asn1Set signerInfs)
        {
            /*
             * RFC3852, section 5.1:
             * IF((certificates is present) AND
             *    (any certificates with a type of other are present)) OR
             *    ((crls is present) AND
             *    (any crls with a type of other are present))
             * THEN version MUST be 5
             * ELSE
             *    IF(certificates is present) AND
             *       (any version 2 attribute certificates are present)
             *    THEN version MUST be 4
             *    ELSE
             *       IF((certificates is present) AND
             *          (any version 1 attribute certificates are present)) OR
             *          (any SignerInfo structures are version 3) OR
             *          (encapContentInfo eContentType is other than id - data)
             *       THEN version MUST be 3
             *       ELSE version MUST be 1
             */

            if (crls != null)
            {
                foreach (var element in crls)
                {
                    var tagged = Asn1TaggedObject.GetOptional(element);
                    if (tagged != null)
                    {
                        // RevocationInfoChoice.other
                        if (tagged.HasContextTag(1))
                            return DerInteger.Five;
                    }
                }
            }

            bool anyV1AttrCerts = false;

            if (certs != null)
            {
                bool anyV2AttrCerts = false;

                foreach (var element in certs)
                {
                    var tagged = Asn1TaggedObject.GetOptional(element);
                    if (tagged != null)
                    {
                        // CertificateChoices.other
                        if (tagged.HasContextTag(3))
                            return DerInteger.Five;

                        // CertificateChoices.v2AttrCert
                        anyV2AttrCerts = anyV2AttrCerts || tagged.HasContextTag(2);

                        // CertificateChoices.v1AttrCert
                        anyV1AttrCerts = anyV1AttrCerts || tagged.HasContextTag(1);
                    }
                }

                if (anyV2AttrCerts)
                    return DerInteger.Four;
            }

            if (anyV1AttrCerts || !CmsObjectIdentifiers.Data.Equals(contentOid) || HasV3SignerInfos(signerInfs))
                return DerInteger.Three;

            return DerInteger.One;
        }

        // (any SignerInfo structures are version 3)
        private static bool HasV3SignerInfos(Asn1Set signerInfs)
        {
            foreach (object obj in signerInfs)
            {
                var signerInfo = SignerInfo.GetInstance(obj);
                if (signerInfo.Version.HasValue(3))
                    return true;
            }
            return false;
        }

        private static Asn1Set ReadOptionalTaggedSet(Asn1Sequence sequence, ref int sequencePosition, int tagNo,
            out bool isBer)
        {
            if (sequencePosition < sequence.Count &&
                sequence[sequencePosition] is Asn1TaggedObject taggedObject &&
                taggedObject.HasContextTag(tagNo))
            {
                var result = Asn1Set.GetInstance(taggedObject, false);
                sequencePosition++;
                isBer = taggedObject is BerTaggedObject;
                return result;
            }

            isBer = default;
            return null;
        }
    }
}
