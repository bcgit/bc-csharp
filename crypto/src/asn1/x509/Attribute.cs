using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AttributeX509
        : Asn1Encodable
    {
        public static AttributeX509 GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeX509 attributeX509)
                return attributeX509;
            return new AttributeX509(Asn1Sequence.GetInstance(obj));
        }

        public static AttributeX509 GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeX509(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static AttributeX509 GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeX509(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_attrType;
        private readonly Asn1Set m_attrValues;

        private AttributeX509(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_attrType = DerObjectIdentifier.GetInstance(seq[0]);
			m_attrValues = Asn1Set.GetInstance(seq[1]);
        }

        public AttributeX509(DerObjectIdentifier attrType, Asn1Set attrValues)
        {
            m_attrType = attrType ?? throw new ArgumentNullException(nameof(attrType));
            m_attrValues = attrValues ?? throw new ArgumentNullException(nameof(attrValues));
        }

        public DerObjectIdentifier AttrType => m_attrType;

        public Asn1Encodable[] GetAttributeValues() => m_attrValues.ToArray();

        public Asn1Set AttrValues => m_attrValues;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Attr ::= Sequence {
         *     attrType OBJECT IDENTIFIER,
         *     attrValues Set OF AttributeValue
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_attrType, m_attrValues);
    }
}
