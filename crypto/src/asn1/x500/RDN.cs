using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.X500
{
    public class RDN : Asn1Encodable
    {
        private Asn1Set values;

        private RDN(Asn1Set values)
        {
            this.values = values;
        }

        public static RDN GetInstance(object obj)
        {
            if (obj is RDN)
            {
                return (RDN)obj;
            }
            else if (obj != null)
            {
                return new RDN(Asn1Set.GetInstance(obj));
            }

            return null;
        }

        /**
         * Create a single valued RDN.
         *
         * @param oid RDN type.
         * @param value RDN value.
         */
        public RDN(DerObjectIdentifier oid, Asn1Encodable value)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(oid);
            v.Add(value);

            this.values = new DerSet(new DerSequence(v));
        }

        public RDN(AttributeTypeAndValue attrTAndV)
        {
            this.values = new DerSet(attrTAndV);
        }

        /**
         * Create a multi-valued RDN.
         *
         * @param aAndVs attribute type/value pairs making up the RDN
         */
        public RDN(AttributeTypeAndValue[] aAndVs)
        {
            this.values = new DerSet(aAndVs);
        }

        public bool isMultiValued()
        {
            return this.values.Count > 1;
        }

        /**
         * Return the number of AttributeTypeAndValue objects in this RDN,
         *
         * @return size of RDN, greater than 1 if multi-valued.
         */
        public int Count
        {
            get
            {
                return this.values.Count;
            }
        }

        public AttributeTypeAndValue GetFirst()
        {
            if (this.values.Count == 0)
            {
                return null;
            }

            return AttributeTypeAndValue.GetInstance(this.values[0]);
        }

        public AttributeTypeAndValue[] GetTypesAndValues()
        {
            AttributeTypeAndValue[] tmp = new AttributeTypeAndValue[values.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = AttributeTypeAndValue.GetInstance(values[i]);
            }

            return tmp;
        }

        /**
         * <pre>
         * RelativeDistinguishedName ::=
         *                     SET OF AttributeTypeAndValue

         * AttributeTypeAndValue ::= SEQUENCE {
         *        type     AttributeType,
         *        value    AttributeValue }
         * </pre>
         * @return this object as an ASN1Primitive type
         */
        public override Asn1Object ToAsn1Object()
        {
            return values;
        }
    }

}