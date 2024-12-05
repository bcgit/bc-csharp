using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class OptionalValidity
        : Asn1Encodable
    {
        public static OptionalValidity GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OptionalValidity optionalValidity)
                return optionalValidity;
            return new OptionalValidity(Asn1Sequence.GetInstance(obj));
        }

        public static OptionalValidity GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OptionalValidity(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OptionalValidity GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OptionalValidity(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Time m_notBefore;
        private readonly Time m_notAfter;

        private OptionalValidity(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_notBefore = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Time.GetTagged);
            m_notAfter = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Time.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public OptionalValidity(Time notBefore, Time notAfter)
        {
            m_notBefore = notBefore;
            m_notAfter = notAfter;
        }

        public virtual Time NotBefore => m_notBefore;

        public virtual Time NotAfter => m_notAfter;

        /**
         * <pre>
         * OptionalValidity ::= SEQUENCE {
         *                        notBefore  [0] Time OPTIONAL,
         *                        notAfter   [1] Time OPTIONAL } --at least one MUST be present
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 0, m_notBefore);
            v.AddOptionalTagged(true, 1, m_notAfter);
            return new DerSequence(v);
        }
    }
}
