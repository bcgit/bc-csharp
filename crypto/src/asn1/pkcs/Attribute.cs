using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The Attribute structure of PKCS#9 as used in PKCS#12 and PKCS#10.</summary>
    public class AttributePkcs
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AttributePkcs"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AttributePkcs"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AttributePkcs"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AttributePkcs GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributePkcs attributePkcs)
                return attributePkcs;
            return new AttributePkcs(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AttributePkcs"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributePkcs"/>.</returns>
        public static AttributePkcs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributePkcs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AttributePkcs"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributePkcs"/>.</returns>
        public static AttributePkcs GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributePkcs(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_attrType;
        private readonly Asn1Set m_attrValues;

        private AttributePkcs(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_attrType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_attrValues = Asn1Utilities.Read(seq, ref pos, Asn1Set.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="AttributePkcs"/>.</summary>
        /// <param name="attrType">The attr type.</param>
        /// <param name="attrValues">The attr values.</param>
        public AttributePkcs(DerObjectIdentifier attrType, Asn1Set attrValues)
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
         * Attr ::= Sequence {
         *     attrType OBJECT IDENTIFIER,
         *     attrValues Set OF AttributeValue
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_attrType, m_attrValues);
    }
}
