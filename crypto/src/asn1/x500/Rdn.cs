using System;

namespace Org.BouncyCastle.Asn1.X500
{
    /**
     * Holding class for a single Relative Distinguished Name (RDN).
     */
    public class Rdn
        : Asn1Encodable
    {
        public static Rdn GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Rdn rdn)
                return rdn;
            return new Rdn(Asn1Set.GetInstance(obj));
        }

        public static Rdn GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Rdn(Asn1Set.GetInstance(taggedObject, declaredExplicit));

        private readonly Asn1Set m_values;

        private Rdn(Asn1Set values)
        {
            // TODO Require minimum size of 1?
            m_values = values;
        }

        /**
         * Create a single valued RDN.
         *
         * @param oid RDN type.
         * @param value RDN value.
         */
        public Rdn(DerObjectIdentifier oid, Asn1Encodable value)
            : this(new AttributeTypeAndValue(oid, value))
        {
        }

        public Rdn(AttributeTypeAndValue attrTAndV)
        {
            m_values = new DerSet(attrTAndV);
        }

        /**
         * Create a multi-valued RDN.
         *
         * @param aAndVs attribute type/value pairs making up the RDN
         */
        public Rdn(AttributeTypeAndValue[] aAndVs)
        {
            m_values = new DerSet(aAndVs);
        }

        public virtual bool IsMultiValued => m_values.Count > 1;

        /**
         * Return the number of AttributeTypeAndValue objects in this RDN,
         *
         * @return size of RDN, greater than 1 if multi-valued.
         */
        public virtual int Count => m_values.Count;

        public virtual AttributeTypeAndValue GetFirst() =>
            m_values.Count == 0 ? null : AttributeTypeAndValue.GetInstance(m_values[0]);

        public virtual AttributeTypeAndValue[] GetTypesAndValues() =>
            m_values.MapElements(AttributeTypeAndValue.GetInstance);

        /**
         * <pre>
         * RelativeDistinguishedName ::=
         *                     SET OF AttributeTypeAndValue

         * AttributeTypeAndValue ::= SEQUENCE {
         *        type     AttributeType,
         *        value    AttributeValue }
         * </pre>
         * @return this object as its ASN1Primitive type
         */
        public override Asn1Object ToAsn1Object() => m_values;
    }
}
