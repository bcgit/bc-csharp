using System;

namespace Org.BouncyCastle.Asn1.X500
{
    /**
     * Holding class for the AttributeTypeAndValue structures that make up an RDN.
     */
    public class AttributeTypeAndValue
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AttributeTypeAndValue"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AttributeTypeAndValue"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AttributeTypeAndValue"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AttributeTypeAndValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeTypeAndValue attributeTypeAndValue)
                return attributeTypeAndValue;
            return new AttributeTypeAndValue(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AttributeTypeAndValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributeTypeAndValue"/>.</returns>
        public static AttributeTypeAndValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeTypeAndValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AttributeTypeAndValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributeTypeAndValue"/>.</returns>
        public static AttributeTypeAndValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeTypeAndValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_type;
        private readonly Asn1Encodable m_value;

        private AttributeTypeAndValue(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_type = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_value = Asn1Utilities.Read(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="AttributeTypeAndValue"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        public AttributeTypeAndValue(DerObjectIdentifier type, Asn1Encodable value)
        {
            m_type = type ?? throw new ArgumentNullException(nameof(type));
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>Gets the type.</summary>
        public virtual DerObjectIdentifier Type => m_type;

        /// <summary>Gets the value.</summary>
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
