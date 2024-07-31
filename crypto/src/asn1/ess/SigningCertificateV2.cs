using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ess
{
    public class SigningCertificateV2
        : Asn1Encodable
    {
        public static SigningCertificateV2 GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is SigningCertificateV2 signingCertificateV2)
                return signingCertificateV2;
            return new SigningCertificateV2(Asn1Sequence.GetInstance(o));
        }

        public static SigningCertificateV2 GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SigningCertificateV2(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SigningCertificateV2 GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SigningCertificateV2(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_certs;
        private readonly Asn1Sequence m_policies;

        private SigningCertificateV2(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Sequence.GetInstance(seq[pos++]);
            m_policies = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public SigningCertificateV2(EssCertIDv2 cert)
        {
            m_certs = new DerSequence(cert);
        }

        public SigningCertificateV2(EssCertIDv2[] certs)
        {
            m_certs = DerSequence.FromElements(certs);
        }

        public SigningCertificateV2(EssCertIDv2[] certs, PolicyInformation[] policies)
        {
            m_certs = new DerSequence(certs);
            m_policies = DerSequence.FromElementsOptional(policies);
        }

        public EssCertIDv2[] GetCerts() => m_certs.MapElements(EssCertIDv2.GetInstance);

        public PolicyInformation[] GetPolicies() => m_policies?.MapElements(PolicyInformation.GetInstance);

        /**
         * The definition of SigningCertificateV2 is
         * <pre>
         * SigningCertificateV2 ::=  SEQUENCE {
         *      certs        SEQUENCE OF EssCertIDv2,
         *      policies     SEQUENCE OF PolicyInformation OPTIONAL
         * }
         * </pre>
         * id-aa-signingCertificateV2 OBJECT IDENTIFIER ::= { iso(1)
         *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
         *    smime(16) id-aa(2) 47 }
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_policies == null
                ?  new DerSequence(m_certs)
                :  new DerSequence(m_certs, m_policies);
        }
    }
}
