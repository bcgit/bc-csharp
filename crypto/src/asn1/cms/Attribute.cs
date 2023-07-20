namespace Org.BouncyCastle.Asn1.Cms
{
    public class Attribute
        : Asn1Encodable
    {
        public static Attribute GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Attribute attribute)
                return attribute;
            return new Attribute(Asn1Sequence.GetInstance(obj));
        }

        public static Attribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new Attribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private DerObjectIdentifier	attrType;
        private Asn1Set				attrValues;

		public Attribute(
            Asn1Sequence seq)
        {
            attrType = (DerObjectIdentifier)seq[0];
            attrValues = (Asn1Set)seq[1];
        }

		public Attribute(
            DerObjectIdentifier attrType,
            Asn1Set             attrValues)
        {
            this.attrType = attrType;
            this.attrValues = attrValues;
        }

        public DerObjectIdentifier AttrType
		{
			get { return attrType; }
		}

		public Asn1Set AttrValues
		{
			get { return attrValues; }
		}

		/**
        * Produce an object suitable for an Asn1OutputStream.
        * <pre>
        * Attribute ::= SEQUENCE {
        *     attrType OBJECT IDENTIFIER,
        *     attrValues SET OF AttributeValue
        * }
        * </pre>
        */
        public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(attrType, attrValues);
        }
    }
}
