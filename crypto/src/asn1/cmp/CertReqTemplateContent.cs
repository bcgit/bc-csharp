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
            if (obj == null)
                return null;
            if (obj is CertReqTemplateContent certReqTemplateContent)
                return certReqTemplateContent;
            return new CertReqTemplateContent(Asn1Sequence.GetInstance(obj));
        }

        public static CertReqTemplateContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqTemplateContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertReqTemplateContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqTemplateContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CertTemplate m_certTemplate;
        private readonly Controls m_keySpec;

        private CertReqTemplateContent(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certTemplate = CertTemplate.GetInstance(seq[pos++]);
            m_keySpec = Asn1Utilities.ReadOptional(seq, ref pos, Controls.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CertReqTemplateContent(CertTemplate certTemplate, Asn1Sequence keySpec)
        {
            m_certTemplate = certTemplate ?? throw new ArgumentNullException(nameof(certTemplate));
            m_keySpec = Controls.GetInstance(keySpec);
        }

        public virtual CertTemplate CertTemplate => m_certTemplate;

        [Obsolete("Use 'KeySpecControls' property instead")]
        public virtual Asn1Sequence KeySpec => Asn1Sequence.GetInstance(m_keySpec?.ToAsn1Object());

        public virtual Controls KeySpecControls => m_keySpec;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_certTemplate);
            v.AddOptional(m_keySpec);
            return new DerSequence(v);
        }
    }
}
