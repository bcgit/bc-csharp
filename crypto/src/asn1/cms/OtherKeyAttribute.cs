using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The OtherKeyAttribute structure of RFC 5652.</summary>
    public class OtherKeyAttribute
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherKeyAttribute"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherKeyAttribute"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherKeyAttribute"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="OtherKeyAttribute"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherKeyAttribute"/>.</returns>
        public static OtherKeyAttribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="OtherKeyAttribute"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="OtherKeyAttribute"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="OtherKeyAttribute"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherKeyAttribute"/>.</returns>
        public static OtherKeyAttribute GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherKeyAttribute(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_keyAttrId;
        private readonly Asn1Encodable m_keyAttr;

        /// <summary>Create a new <see cref="OtherKeyAttribute"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public OtherKeyAttribute(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyAttrId = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_keyAttr = Asn1Utilities.ReadOptional(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OtherKeyAttribute"/>.</summary>
        /// <param name="keyAttrId">The key attr id.</param>
        /// <param name="keyAttr">The key attr.</param>
        public OtherKeyAttribute(DerObjectIdentifier keyAttrId, Asn1Encodable keyAttr)
        {
            m_keyAttrId = keyAttrId ?? throw new ArgumentNullException(nameof(keyAttrId));
            m_keyAttr = keyAttr;
        }

        /// <summary>Gets the key attr id.</summary>
        public DerObjectIdentifier KeyAttrId => m_keyAttrId;

        /// <summary>Gets the key attr.</summary>
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
