using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * <pre>
     * DeltaCertificateDescriptor ::= SEQUENCE {
     *   serialNumber          CertificateSerialNumber,
     *   signature             [0] EXPLICIT AlgorithmIdentifier {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
     *   issuer                [1] EXPLICIT Name OPTIONAL,
     *   validity              [2] EXPLICIT Validity OPTIONAL,
     *   subject               [3] EXPLICIT Name OPTIONAL,
     *   subjectPublicKeyInfo  SubjectPublicKeyInfo,
     *   extensions            [4] EXPLICIT Extensions{CertExtensions} OPTIONAL,
     *   signatureValue        BIT STRING
     * }
     * </pre>
     */
    public class DeltaCertificateDescriptor
        : Asn1Encodable
    {
        public static DeltaCertificateDescriptor GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DeltaCertificateDescriptor deltaCertificateDescriptor)
                return deltaCertificateDescriptor;
            return new DeltaCertificateDescriptor(Asn1Sequence.GetInstance(obj));
        }

        public static DeltaCertificateDescriptor GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DeltaCertificateDescriptor(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static DeltaCertificateDescriptor GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DeltaCertificateDescriptor(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static DeltaCertificateDescriptor FromExtensions(X509Extensions extensions)
        {
            return GetInstance(
                X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.DRAFT_DeltaCertificateDescriptor));
        }

        private readonly DerInteger m_serialNumber;
        private readonly AlgorithmIdentifier m_signature;
        private readonly X509Name m_issuer;
        private readonly Validity m_validity;
        private readonly X509Name m_subject;
        private readonly SubjectPublicKeyInfo m_subjectPublicKeyInfo;
        private readonly X509Extensions m_extensions;
        private readonly DerBitString m_signatureValue;

        private DeltaCertificateDescriptor(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 8)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_serialNumber = DerInteger.GetInstance(seq[pos++]);
            m_signature = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetTagged);
            m_issuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509Name.GetTagged); // CHOICE Name
            m_validity = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Validity.GetTagged);
            m_subject = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, X509Name.GetTagged); // CHOICE Name
            m_subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(seq[pos++]);
            m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, true, X509Extensions.GetTagged);
            m_signatureValue = DerBitString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DeltaCertificateDescriptor(DerInteger serialNumber, AlgorithmIdentifier signature, X509Name issuer,
            Validity validity, X509Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo,
            X509Extensions extensions, DerBitString signatureValue)
        {
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
            m_signature = signature;
            m_issuer = issuer;
            m_validity = validity;
            m_subject = subject;
            m_subjectPublicKeyInfo = subjectPublicKeyInfo ?? throw new ArgumentNullException(nameof(subjectPublicKeyInfo));
            m_extensions = extensions;
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
        }

        public X509Extensions Extensions => m_extensions;

        public X509Name Issuer => m_issuer;

        public DerInteger SerialNumber => m_serialNumber;

        public AlgorithmIdentifier Signature => m_signature;

        public DerBitString SignatureValue => m_signatureValue;

        public X509Name Subject => m_subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_subjectPublicKeyInfo;

        public Validity Validity => m_validity;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(8);
            v.Add(m_serialNumber);
            v.AddOptionalTagged(true, 0, m_signature);
            v.AddOptionalTagged(true, 1, m_issuer); // CHOICE
            v.AddOptionalTagged(true, 2, m_validity);
            v.AddOptionalTagged(true, 3, m_subject); // CHOICE
            v.Add(m_subjectPublicKeyInfo);
            v.AddOptionalTagged(true, 4, m_extensions);
            v.Add(m_signatureValue);
            return new DerSequence(v);
        }
    }
}
