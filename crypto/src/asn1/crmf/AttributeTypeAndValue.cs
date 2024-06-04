using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class AttributeTypeAndValue
        : Asn1Encodable
    {
        public static AttributeTypeAndValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeTypeAndValue attributeTypeAndValue)
                return attributeTypeAndValue;
            return new AttributeTypeAndValue(Asn1Sequence.GetInstance(obj));
        }

        public static AttributeTypeAndValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new AttributeTypeAndValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerObjectIdentifier m_type;
        private readonly Asn1Encodable m_value;

        private AttributeTypeAndValue(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_type = DerObjectIdentifier.GetInstance(seq[0]);
            m_value = seq[1];
        }

        public AttributeTypeAndValue(string oid, Asn1Encodable value)
            : this(new DerObjectIdentifier(oid), value)
        {
        }

        public AttributeTypeAndValue(DerObjectIdentifier type, Asn1Encodable value)
        {
            m_type = type ?? throw new ArgumentNullException(nameof(type));
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public virtual DerObjectIdentifier Type => m_type;

        public virtual Asn1Encodable Value => m_value;

        /**
         * <pre>
         * AttributeTypeAndValue ::= SEQUENCE {
         *           type         OBJECT IDENTIFIER,
         *           value        ANY DEFINED BY type }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_type, m_value);
    }
}
