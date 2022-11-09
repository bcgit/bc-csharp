using System;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * GenMsg:    {id-it 19}, &lt; absent &gt;
     * GenRep:    {id-it 19}, CertReqTemplateContent | &lt; absent &gt;
     * <p>
     * CertReqTemplateValue  ::= CertReqTemplateContent
     * </p><p>
     * CertReqTemplateContent ::= SEQUENCE {
     * certTemplate           CertTemplate,
     * keySpec                Controls OPTIONAL }
     * </p><p>
     * Controls  ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue
     * </p>
     */
    public class CertReqTemplateContent
        : Asn1Encodable
    {
        public static CertReqTemplateContent GetInstance(object obj)
        {
            if (obj is CertReqTemplateContent certReqTemplateContent)
                return certReqTemplateContent;

            if (obj != null)
                return new CertReqTemplateContent(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private readonly CertTemplate m_certTemplate;
        private readonly Asn1Sequence m_keySpec;

        private CertReqTemplateContent(Asn1Sequence seq)
        {
            if (seq.Count != 1 && seq.Count != 2)
                throw new ArgumentException("expected sequence size of 1 or 2");

            m_certTemplate = CertTemplate.GetInstance(seq[0]);

            if (seq.Count > 1)
            {
                m_keySpec = Asn1Sequence.GetInstance(seq[1]);
            }
        }

        public CertReqTemplateContent(CertTemplate certTemplate, Asn1Sequence keySpec)
        {
            m_certTemplate = certTemplate;
            m_keySpec = keySpec;
        }

        public virtual CertTemplate CertTemplate => m_certTemplate;

        public virtual Asn1Sequence KeySpec => m_keySpec;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_certTemplate);
            v.AddOptional(m_keySpec);
            return new DerSequence(v);
        }
    }
}
