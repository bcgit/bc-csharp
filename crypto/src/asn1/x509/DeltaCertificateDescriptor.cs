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
        /// <summary>Return an <see cref="DeltaCertificateDescriptor"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DeltaCertificateDescriptor"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DeltaCertificateDescriptor"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DeltaCertificateDescriptor GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DeltaCertificateDescriptor deltaCertificateDescriptor)
                return deltaCertificateDescriptor;
            return new DeltaCertificateDescriptor(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DeltaCertificateDescriptor"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DeltaCertificateDescriptor"/>.</returns>
        public static DeltaCertificateDescriptor GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DeltaCertificateDescriptor(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="DeltaCertificateDescriptor"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DeltaCertificateDescriptor"/>.</returns>
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

            m_serialNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_signature = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetTagged);
            m_issuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509Name.GetTagged); // CHOICE Name
            m_validity = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Validity.GetTagged);
            m_subject = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, X509Name.GetTagged); // CHOICE Name
            m_subjectPublicKeyInfo = Asn1Utilities.Read(seq, ref pos, SubjectPublicKeyInfo.GetInstance);
            m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, true, X509Extensions.GetTagged);
            m_signatureValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="DeltaCertificateDescriptor"/>.</summary>
        /// <param name="serialNumber">The serial number.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="issuer">The issuer.</param>
        /// <param name="validity">The validity.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="subjectPublicKeyInfo">The subject public key info.</param>
        /// <param name="extensions">The extensions.</param>
        /// <param name="signatureValue">The signature value.</param>
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

        /// <summary>Gets the extensions.</summary>
        public X509Extensions Extensions => m_extensions;

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_issuer;

        /// <summary>Gets the serial number.</summary>
        public DerInteger SerialNumber => m_serialNumber;

        /// <summary>Gets the signature.</summary>
        public AlgorithmIdentifier Signature => m_signature;

        /// <summary>Gets the signature value.</summary>
        public DerBitString SignatureValue => m_signatureValue;

        /// <summary>Gets the subject.</summary>
        public X509Name Subject => m_subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_subjectPublicKeyInfo;

        public Validity Validity => m_validity;

        /// <inheritdoc/>
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
