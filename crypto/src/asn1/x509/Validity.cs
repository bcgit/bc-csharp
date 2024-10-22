using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class Validity
        : Asn1Encodable
    {
        public static Validity GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Validity validity)
                return validity;
            return new Validity(Asn1Sequence.GetInstance(obj));
        }

        public static Validity GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Validity(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Validity GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Validity(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Time m_notBefore;
        private readonly Time m_notAfter;

        private Validity(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_notBefore = Time.GetInstance(seq[0]);
            m_notAfter = Time.GetInstance(seq[1]);
        }

        public Validity(Time notBefore, Time notAfter)
        {
            m_notBefore = notBefore ?? throw new ArgumentNullException(nameof(notBefore));
            m_notAfter = notAfter ?? throw new ArgumentNullException(nameof(notAfter));
        }

        public Time NotBefore => m_notBefore;

        public Time NotAfter => m_notAfter;

        /**
         * <pre>
         * Validity ::= SEQUENCE {
         *   notBefore      Time,
         *   notAfter       Time  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_notBefore, m_notAfter);
    }
}
