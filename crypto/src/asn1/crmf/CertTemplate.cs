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

        public static CertTemplate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CertTemplate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

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

            m_version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, DerInteger.GetInstance);
            m_serialNumber = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerInteger.GetInstance);
            m_signingAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, AlgorithmIdentifier.GetInstance);
            m_issuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, X509Name.GetInstance); // CHOICE Name
            m_validity = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, false, OptionalValidity.GetInstance);
            m_subject = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 5, true, X509Name.GetInstance); // CHOICE Name
            m_publicKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 6, false, SubjectPublicKeyInfo.GetInstance);
            m_issuerUID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 7, false, DerBitString.GetInstance);
            m_subjectUID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 8, false, DerBitString.GetInstance);
            m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 9, false, X509Extensions.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_seq = seq;
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
    }
}
