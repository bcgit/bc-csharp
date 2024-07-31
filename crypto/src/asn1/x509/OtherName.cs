using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The OtherName object.
     * <pre>
     * OtherName ::= SEQUENCE {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     * </pre>
     */
    public class OtherName
        : Asn1Encodable
    {
        /**
         * OtherName factory method.
         * @param obj the object used to construct an instance of <code>
         * OtherName</code>. It must be an instance of <code>OtherName
         * </code> or <code>ASN1Sequence</code>.
         * @return the instance of <code>OtherName</code> built from the
         * supplied object.
         * @throws java.lang.IllegalArgumentException if the object passed
         * to the factory is not an instance of <code>OtherName</code> or something that
         * can be converted into an appropriate <code>ASN1Sequence</code>.
         */
        public static OtherName GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherName otherName)
                return otherName;
            return new OtherName(Asn1Sequence.GetInstance(obj));
        }

        public static OtherName GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherName(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OtherName GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherName(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_typeID;
        private readonly Asn1Encodable m_value;

        private OtherName(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_typeID = DerObjectIdentifier.GetInstance(seq[0]);
            m_value = Asn1TaggedObject.GetInstance(seq[1], Asn1Tags.ContextSpecific, 0).GetExplicitBaseObject();
        }

        /**
         * Base constructor.
         * @param typeID the type of the other name.
         * @param value the ANY object that represents the value.
         */
        public OtherName(DerObjectIdentifier typeID, Asn1Encodable value)
        {
            m_typeID = typeID ?? throw new ArgumentNullException(nameof(typeID));
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public virtual DerObjectIdentifier TypeID => m_typeID;

        public Asn1Encodable Value => m_value;

        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_typeID, new DerTaggedObject(true, 0, m_value));
    }
}
