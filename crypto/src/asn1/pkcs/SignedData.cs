using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * a Pkcs#7 signed data object.
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

        public static SignedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new SignedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_version;
        private readonly Asn1Set m_digestAlgorithms;
        private readonly ContentInfo m_contentInfo;
        private readonly Asn1Set m_certificates;
        private readonly Asn1Set m_crls;
        private readonly Asn1Set m_signerInfos;

        private SignedData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_digestAlgorithms = Asn1Set.GetInstance(seq[pos++]);
            m_contentInfo = ContentInfo.GetInstance(seq[pos++]);
            m_certificates = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetInstance);
            m_crls = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetInstance);
            m_signerInfos = Asn1Set.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] Improve parameter names
        public SignedData(
            DerInteger _version,
            Asn1Set _digestAlgorithms,
            ContentInfo _contentInfo,
            Asn1Set _certificates,
            Asn1Set _crls,
            Asn1Set _signerInfos)
        {
            m_version = _version ?? throw new ArgumentNullException(nameof(_version));
            m_digestAlgorithms = _digestAlgorithms ?? throw new ArgumentNullException(nameof(_digestAlgorithms));
            m_contentInfo = _contentInfo ?? throw new ArgumentNullException(nameof(_contentInfo));
            m_certificates = _certificates;
            m_crls = _crls;
            m_signerInfos = _signerInfos ?? throw new ArgumentNullException(nameof(_signerInfos));
        }

        public DerInteger Version => m_version;

        public Asn1Set DigestAlgorithms => m_digestAlgorithms;

        public ContentInfo ContentInfo => m_contentInfo;

        public Asn1Set Certificates => m_certificates;

        public Asn1Set Crls => m_crls;

        public Asn1Set SignerInfos => m_signerInfos;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  SignedData ::= Sequence {
         *      version Version,
         *      digestAlgorithms DigestAlgorithmIdentifiers,
         *      contentInfo ContentInfo,
         *      certificates
         *          [0] IMPLICIT ExtendedCertificatesAndCertificates
         *                   OPTIONAL,
         *      crls
         *          [1] IMPLICIT CertificateRevocationLists OPTIONAL,
         *      signerInfos SignerInfos }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);
            v.Add(m_version, m_digestAlgorithms, m_contentInfo);
            v.AddOptionalTagged(false, 0, m_certificates);
            v.AddOptionalTagged(false, 1, m_crls);
            v.Add(m_signerInfos);
            return new BerSequence(v);
        }
    }
}
