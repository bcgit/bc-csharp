using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The Attribute structure of RFC 5652: an attribute type and its set of values.</summary>
    public class Attribute
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Attribute"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Attribute"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Attribute"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="Attribute"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Attribute"/>.</returns>
        public static Attribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Attribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="Attribute"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Attribute"/>.</returns>
        public static Attribute GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new Attribute(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_attrType;
        private readonly Asn1Set m_attrValues;

        /// <summary>Create a new <see cref="Attribute"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public Attribute(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_attrType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_attrValues = Asn1Utilities.Read(seq, ref pos, Asn1Set.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Attribute"/>.</summary>
        /// <param name="attrType">The attr type.</param>
        /// <param name="attrValues">The attr values.</param>
        public Attribute(DerObjectIdentifier attrType, Asn1Set attrValues)
        {
            m_attrType = attrType ?? throw new ArgumentNullException(nameof(attrType));
            m_attrValues = attrValues ?? throw new ArgumentNullException(nameof(attrValues));
        }

        /// <summary>Gets the attr type.</summary>
        public DerObjectIdentifier AttrType => m_attrType;

        /// <summary>Gets the attr values.</summary>
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
