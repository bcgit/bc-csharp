using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class AttributePkcs
        : Asn1Encodable
    {
        public static AttributePkcs GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributePkcs attributePkcs)
                return attributePkcs;
            return new AttributePkcs(Asn1Sequence.GetInstance(obj));
		}

        public static AttributePkcs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new AttributePkcs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerObjectIdentifier m_attrType;
        private readonly Asn1Set m_attrValues;

        private AttributePkcs(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_attrType = DerObjectIdentifier.GetInstance(seq[0]);
            m_attrValues = Asn1Set.GetInstance(seq[1]);
        }

		public AttributePkcs(DerObjectIdentifier attrType, Asn1Set attrValues)
        {
            m_attrType = attrType ?? throw new ArgumentNullException(nameof(attrType));
            m_attrValues = attrValues ?? throw new ArgumentNullException(nameof(attrValues));
        }

        public DerObjectIdentifier AttrType => m_attrType;

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
