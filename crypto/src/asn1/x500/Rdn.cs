using System;

namespace Org.BouncyCastle.Asn1.X500
{
    /// <summary>Holding class for a single Relative Distinguished Name (RDN).</summary>
    public class Rdn
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Rdn"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Rdn"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Rdn"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Rdn GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Rdn rdn)
                return rdn;
            return new Rdn(Asn1Set.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Rdn"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Rdn"/>.</returns>
        public static Rdn GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Rdn(Asn1Set.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Rdn"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Rdn"/>.</returns>
        public static Rdn GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Rdn(Asn1Set.GetTagged(taggedObject, declaredExplicit));

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

        /// <summary>Create a new <see cref="Rdn"/>.</summary>
        /// <param name="attrTAndV">The attr t and v.</param>
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

        /// <summary>Gets a value indicating whether this is multi valued.</summary>
        public virtual bool IsMultiValued => m_values.Count > 1;

        /**
         * Return the number of AttributeTypeAndValue objects in this RDN,
         *
         * @return size of RDN, greater than 1 if multi-valued.
         */
        public virtual int Count => m_values.Count;

        /// <summary>Return the first.</summary>
        public virtual AttributeTypeAndValue GetFirst() =>
            m_values.Count == 0 ? null : AttributeTypeAndValue.GetInstance(m_values[0]);

        /// <summary>Return the types and values.</summary>
        public virtual AttributeTypeAndValue[] GetTypesAndValues() =>
            m_values.MapElements(AttributeTypeAndValue.GetInstance);

        internal int CollectAttributeTypes(DerObjectIdentifier[] oids, int oidsOff)
        {
            int count = m_values.Count;
            for (int i = 0; i < count; ++i)
            {
                AttributeTypeAndValue attr = AttributeTypeAndValue.GetInstance(m_values[i]);
                oids[oidsOff + i] = attr.Type;
            }
            return m_values.Count;
        }

        internal bool ContainsAttributeType(DerObjectIdentifier attributeType)
        {
            int count = m_values.Count;
            for (int i = 0; i < count; ++i)
            {
                AttributeTypeAndValue attr = AttributeTypeAndValue.GetInstance(m_values[i]);
                if (attr.Type.Equals(attributeType))
                    return true;
            }
            return false;
        }

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
