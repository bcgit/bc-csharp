using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * This extension may contain further X.500 attributes of the subject. See also
     * RFC 3039.
     *
     * <pre>
     *     SubjectDirectoryAttributes ::= Attributes
     *     Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
     *     Attribute ::= SEQUENCE
     *     {
     *       type AttributeType
     *       values SET OF AttributeValue
     *     }
     *
     *     AttributeType ::= OBJECT IDENTIFIER
     *     AttributeValue ::= ANY DEFINED BY AttributeType
     * </pre>
     *
     * @see Org.BouncyCastle.Asn1.X509.X509Name for AttributeType ObjectIdentifiers.
     */
    public class SubjectDirectoryAttributes
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SubjectDirectoryAttributes"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SubjectDirectoryAttributes"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SubjectDirectoryAttributes"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SubjectDirectoryAttributes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SubjectDirectoryAttributes subjectDirectoryAttributes)
                return subjectDirectoryAttributes;
            return new SubjectDirectoryAttributes(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SubjectDirectoryAttributes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SubjectDirectoryAttributes"/>.</returns>
        public static SubjectDirectoryAttributes GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectDirectoryAttributes(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SubjectDirectoryAttributes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SubjectDirectoryAttributes"/>.</returns>
        public static SubjectDirectoryAttributes GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectDirectoryAttributes(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_attributes;

        /**
         * Constructor from Asn1Sequence.
         *
         * The sequence is of type SubjectDirectoryAttributes:
         *
         * <pre>
         *      SubjectDirectoryAttributes ::= Attributes
         *      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
         *      Attribute ::= SEQUENCE
         *      {
         *        type AttributeType
         *        values SET OF AttributeValue
         *      }
         *
         *      AttributeType ::= OBJECT IDENTIFIER
         *      AttributeValue ::= ANY DEFINED BY AttributeType
         * </pre>
         *
         * @param seq
         *            The ASN.1 sequence.
         */
        private SubjectDirectoryAttributes(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            m_attributes = DerSequence.Map(seq, AttributeX509.GetInstance);
        }

        /**
         * Constructor from an ArrayList of attributes.
         *
         * The ArrayList consists of attributes of type {@link Attribute Attribute}
         *
         * @param attributes The attributes.
         *
         */
        public SubjectDirectoryAttributes(IList<AttributeX509> attributes)
        {
            if (attributes == null)
                throw new ArgumentNullException(nameof(attributes));
            if (attributes.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(attributes));

            m_attributes = DerSequence.Map(Asn1EncodableVector.FromEnumerable(attributes), AttributeX509.GetInstance);
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         *
         * Returns:
         *
         * <pre>
         *      SubjectDirectoryAttributes ::= Attributes
         *      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
         *      Attribute ::= SEQUENCE
         *      {
         *        type AttributeType
         *        values SET OF AttributeValue
         *      }
         *
         *      AttributeType ::= OBJECT IDENTIFIER
         *      AttributeValue ::= ANY DEFINED BY AttributeType
         * </pre>
         *
         * @return a DERObject
         */
        public override Asn1Object ToAsn1Object() => m_attributes;

        /// <summary>Gets the attributes.</summary>
        public IEnumerable<AttributeX509> Attributes =>
            CollectionUtilities.Select(m_attributes, AttributeX509.GetInstance);
    }
}
