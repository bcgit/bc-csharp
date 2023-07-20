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

        public static CrlStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CrlStatus(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly CrlSource m_source;
        private readonly Time m_thisUpdate;

        private CrlStatus(Asn1Sequence sequence)
        {
            int count = sequence.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("expected sequence size of 1 or 2, got " + count);

            m_source = CrlSource.GetInstance(sequence[0]);

            if (sequence.Count == 2)
            {
                m_thisUpdate = Time.GetInstance(sequence[1]);
            }
        }

        public CrlStatus(CrlSource source, Time thisUpdate)
        {
            m_source = source;
            m_thisUpdate = thisUpdate;
        }

        public virtual CrlSource Source => m_source;

        public virtual Time ThisUpdate => m_thisUpdate;

        public override Asn1Object ToAsn1Object()
        {
            if (m_thisUpdate == null)
                return new DerSequence(m_source);

            return new DerSequence(m_source, m_thisUpdate);
        }
    }
}
