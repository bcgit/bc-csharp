using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertTemplate
        : Asn1Encodable
    {
        public static CertTemplate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertTemplate certTemplate)
                return certTemplate;
            return new CertTemplate(Asn1Sequence.GetInstance(obj));
        }

        public static CertTemplate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertTemplate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertTemplate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertTemplate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_seq;

        private readonly DerInteger m_version;
        private readonly DerInteger m_serialNumber;
        private readonly AlgorithmIdentifier m_signingAlg;
        private readonly X509Name m_issuer;
        private readonly OptionalValidity m_validity;
        private readonly X509Name m_subject;
        private readonly SubjectPublicKeyInfo m_publicKey;
        private readonly DerBitString m_issuerUID;
        private readonly DerBitString m_subjectUID;
        private readonly X509Extensions m_extensions;

        private CertTemplate(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 0 || count > 10)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, DerInteger.GetTagged);
            m_serialNumber = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerInteger.GetTagged);
            m_signingAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, AlgorithmIdentifier.GetTagged);
            m_issuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, X509Name.GetTagged); // CHOICE Name
            m_validity = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, false, OptionalValidity.GetTagged);
            m_subject = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 5, true, X509Name.GetTagged); // CHOICE Name
            m_publicKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 6, false, SubjectPublicKeyInfo.GetTagged);
            m_issuerUID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 7, false, DerBitString.GetTagged);
            m_subjectUID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 8, false, DerBitString.GetTagged);
            m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 9, false, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            Rfc4211Asn1Utilities.CheckValidityFieldPresent(m_validity);

            m_seq = seq;
        }

        public CertTemplate(DerInteger version, DerInteger serialNumber, AlgorithmIdentifier signingAlg,
            X509Name issuer, OptionalValidity validity, X509Name subject, SubjectPublicKeyInfo publicKey,
            DerBitString issuerUID, DerBitString subjectUID, X509Extensions extensions)
        {
            m_version = version;
            m_serialNumber = serialNumber;
            m_signingAlg = signingAlg;
            m_issuer = issuer;
            m_validity = Rfc4211Asn1Utilities.CheckValidityFieldPresent(validity);
            m_subject = subject;
            m_publicKey = publicKey;
            m_issuerUID = issuerUID;
            m_subjectUID = subjectUID;
            m_extensions = extensions;

            m_seq = CreateSequence();
        }

        public virtual int Version => m_version.IntValueExact;

        public virtual DerInteger SerialNumber => m_serialNumber;

        public virtual AlgorithmIdentifier SigningAlg => m_signingAlg;

        public virtual X509Name Issuer => m_issuer;

        public virtual OptionalValidity Validity => m_validity;

        public virtual X509Name Subject => m_subject;

        public virtual SubjectPublicKeyInfo PublicKey => m_publicKey;

        public virtual DerBitString IssuerUID => m_issuerUID;

        public virtual DerBitString SubjectUID => m_subjectUID;

        public virtual X509Extensions Extensions => m_extensions;

        /**
         * <pre>
         *  CertTemplate ::= SEQUENCE {
         *      version      [0] Version               OPTIONAL,
         *      serialNumber [1] INTEGER               OPTIONAL,
         *      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
         *      issuer       [3] Name                  OPTIONAL,
         *      validity     [4] OptionalValidity      OPTIONAL,
         *      subject      [5] Name                  OPTIONAL,
         *      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
         *      issuerUID    [7] UniqueIdentifier      OPTIONAL,
         *      subjectUID   [8] UniqueIdentifier      OPTIONAL,
         *      extensions   [9] Extensions            OPTIONAL }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_seq;

        private Asn1Sequence CreateSequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(10);
            v.AddOptionalTagged(false, 0, m_version);
            v.AddOptionalTagged(false, 1, m_serialNumber);
            v.AddOptionalTagged(false, 2, m_signingAlg);
            v.AddOptionalTagged(true, 3, m_issuer); // CHOICE
            v.AddOptionalTagged(false, 4, m_validity);
            v.AddOptionalTagged(true, 5, m_subject); // CHOICE
            v.AddOptionalTagged(false, 6, m_publicKey);
            v.AddOptionalTagged(false, 7, m_issuerUID);
            v.AddOptionalTagged(false, 8, m_subjectUID);
            v.AddOptionalTagged(false, 9, m_extensions);
            return new DerSequence(v);
        }
    }
}
