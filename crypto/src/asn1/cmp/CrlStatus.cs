using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * CRLStatus ::= SEQUENCE {
     * source       CRLSource,
     * thisUpdate   Time OPTIONAL }
     */
    public class CrlStatus
        : Asn1Encodable
    {
        public static CrlStatus GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlStatus crlStatus)
                return crlStatus;
            return new CrlStatus(Asn1Sequence.GetInstance(obj));
        }

        public static CrlStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlStatus(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CrlStatus GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlStatus(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CrlSource m_source;
        private readonly Time m_thisUpdate;

        private CrlStatus(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_source = CrlSource.GetInstance(seq[pos++]);
            m_thisUpdate = Asn1Utilities.ReadOptional(seq, ref pos, Time.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public CrlStatus(CrlSource source, Time thisUpdate)
        {
            m_source = source ?? throw new ArgumentNullException(nameof(source));
            m_thisUpdate = thisUpdate;
        }

        public virtual CrlSource Source => m_source;

        public virtual Time ThisUpdate => m_thisUpdate;

        public override Asn1Object ToAsn1Object()
        {
            return m_thisUpdate == null
                ?  new DerSequence(m_source)
                :  new DerSequence(m_source, m_thisUpdate);
        }
    }
}
