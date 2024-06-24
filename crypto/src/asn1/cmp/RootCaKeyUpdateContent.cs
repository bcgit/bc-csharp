using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * GenMsg:    {id-it 20}, RootCaCertValue | &lt; absent &gt;
     * GenRep:    {id-it 18}, RootCaKeyUpdateContent | &lt; absent &gt;
     * <p>
     * RootCaCertValue ::= CMPCertificate
     * </p><p>
     * RootCaKeyUpdateValue ::= RootCaKeyUpdateContent
     * </p><p>
     * RootCaKeyUpdateContent ::= SEQUENCE {
     * newWithNew       CMPCertificate,
     * newWithOld   [0] CMPCertificate OPTIONAL,
     * oldWithNew   [1] CMPCertificate OPTIONAL
     * }
     * </p>
     */
    public class RootCaKeyUpdateContent
        : Asn1Encodable
    {
        public static RootCaKeyUpdateContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RootCaKeyUpdateContent rootCaKeyUpdateContent)
                return rootCaKeyUpdateContent;
            return new RootCaKeyUpdateContent(Asn1Sequence.GetInstance(obj));
        }

        public static RootCaKeyUpdateContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new RootCaKeyUpdateContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly CmpCertificate m_newWithNew;
        private readonly CmpCertificate m_newWithOld;
        private readonly CmpCertificate m_oldWithNew;

        public RootCaKeyUpdateContent(CmpCertificate newWithNew, CmpCertificate newWithOld, CmpCertificate oldWithNew)
        {
            m_newWithNew = newWithNew ?? throw new ArgumentNullException(nameof(newWithNew));
            m_newWithOld = newWithOld;
            m_oldWithNew = oldWithNew;
        }

        private RootCaKeyUpdateContent(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_newWithNew = CmpCertificate.GetInstance(seq[pos++]);
            m_newWithOld = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, CmpCertificate.GetTagged);
            m_oldWithNew = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, CmpCertificate.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual CmpCertificate NewWithNew => m_newWithNew;

        public virtual CmpCertificate NewWithOld => m_newWithOld;

        public virtual CmpCertificate OldWithNew => m_oldWithNew;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_newWithNew);
            v.AddOptionalTagged(true, 0, m_newWithOld);
            v.AddOptionalTagged(true, 1, m_oldWithNew);
            return new DerSequence(v);
        }
    }
}
