using System;

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
#pragma warning disable CS0618 // Type or member is obsolete
            return new Attribute(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static Attribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Attribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static Attribute GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Attribute(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_attrType;
        private readonly Asn1Set m_attrValues;

        [Obsolete("Use 'GetInstance' instead")]
        public Attribute(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_attrType = DerObjectIdentifier.GetInstance(seq[0]);
            m_attrValues = Asn1Set.GetInstance(seq[1]);
        }

        public Attribute(DerObjectIdentifier attrType, Asn1Set attrValues)
        {
            m_attrType = attrType ?? throw new ArgumentNullException(nameof(attrType));
            m_attrValues = attrValues ?? throw new ArgumentNullException(nameof(attrValues));
        }

        public DerObjectIdentifier AttrType => m_attrType;

        public Asn1Set AttrValues => m_attrValues;

		/**
        * Produce an object suitable for an Asn1OutputStream.
        * <pre>
        * Attribute ::= SEQUENCE {
        *     attrType OBJECT IDENTIFIER,
        *     attrValues SET OF AttributeValue
        * }
        * </pre>
        */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_attrType, m_attrValues);
    }
}
