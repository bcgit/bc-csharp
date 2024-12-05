using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OtherKeyAttribute
        : Asn1Encodable
    {
        public static OtherKeyAttribute GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherKeyAttribute otherKeyAttribute)
                return otherKeyAttribute;
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static OtherKeyAttribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static OtherKeyAttribute GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OtherKeyAttribute otherKeyAttribute)
                return otherKeyAttribute;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
#pragma warning disable CS0618 // Type or member is obsolete
                return new OtherKeyAttribute(asn1Sequence);
#pragma warning restore CS0618 // Type or member is obsolete

            return null;
        }

        public static OtherKeyAttribute GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_keyAttrId;
        private readonly Asn1Encodable m_keyAttr;

        [Obsolete("Use 'GetInstance' instead")]
        public OtherKeyAttribute(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyAttrId = DerObjectIdentifier.GetInstance(seq[0]);
            m_keyAttr = count == 1 ? null : seq[1];
        }

        public OtherKeyAttribute(DerObjectIdentifier keyAttrId, Asn1Encodable keyAttr)
        {
            m_keyAttrId = keyAttrId ?? throw new ArgumentNullException(nameof(keyAttrId));
            m_keyAttr = keyAttr;
        }

        public DerObjectIdentifier KeyAttrId => m_keyAttrId;

        public Asn1Encodable KeyAttr => m_keyAttr;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OtherKeyAttribute ::= Sequence {
         *     keyAttrId OBJECT IDENTIFIER,
         *     keyAttr ANY DEFINED BY keyAttrId OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_keyAttr == null
                ?  new DerSequence(m_keyAttrId)
                :  new DerSequence(m_keyAttrId, m_keyAttr);
        }
    }
}
