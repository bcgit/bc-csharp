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
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly CmpCertificate m_newWithNew;
        private readonly CmpCertificate m_newWithOld;
        private readonly CmpCertificate m_oldWithNew;

        public RootCaKeyUpdateContent(CmpCertificate newWithNew, CmpCertificate newWithOld, CmpCertificate oldWithNew)
        {
            if (newWithNew == null)
                throw new ArgumentNullException(nameof(newWithNew));

            m_newWithNew = newWithNew;
            m_newWithOld = newWithOld;
            m_oldWithNew = oldWithNew;
        }

        private RootCaKeyUpdateContent(Asn1Sequence seq)
        {
            if (seq.Count < 1 || seq.Count > 3)
                throw new ArgumentException("expected sequence of 1 to 3 elements only");

            CmpCertificate newWithNew = CmpCertificate.GetInstance(seq[0]);
            CmpCertificate newWithOld = null;
            CmpCertificate oldWithNew = null;

            for (int pos = 1; pos < seq.Count; ++pos)
            {
                Asn1TaggedObject ato = Asn1TaggedObject.GetInstance(seq[pos]);

                if (ato.HasContextTag(0))
                {
                    newWithOld = CmpCertificate.GetInstance(ato, true);
                }
                else if (ato.HasContextTag(1))
                {
                    oldWithNew = CmpCertificate.GetInstance(ato, true);
                }
            }

            m_newWithNew = newWithNew;
            m_newWithOld = newWithOld;
            m_oldWithNew = oldWithNew;
        }

        public virtual CmpCertificate NewWithNew => m_newWithNew;

        public virtual CmpCertificate NewWithOld => m_newWithOld;

        public virtual CmpCertificate OldWithNew => m_oldWithNew;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_newWithNew);
            v.AddOptionalTagged(true, 0, m_newWithOld);
            v.AddOptionalTagged(true, 1, m_oldWithNew);
            return new DerSequence(v);
        }
    }
}
