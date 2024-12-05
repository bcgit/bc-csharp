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
        public static SubjectDirectoryAttributes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SubjectDirectoryAttributes subjectDirectoryAttributes)
                return subjectDirectoryAttributes;
            return new SubjectDirectoryAttributes(Asn1Sequence.GetInstance(obj));
        }

        public static SubjectDirectoryAttributes GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectDirectoryAttributes(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SubjectDirectoryAttributes GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectDirectoryAttributes(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly List<AttributeX509> m_attributes;

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
            m_attributes = new List<AttributeX509>(seq.Count);
            foreach (var element in seq)
			{
				m_attributes.Add(AttributeX509.GetInstance(element));
			}
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
			m_attributes = new List<AttributeX509>(attributes);
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
		public override Asn1Object ToAsn1Object() => DerSequence.WithElements(m_attributes.ToArray());

        /**
		 * @return Returns the attributes.
		 */
		public IEnumerable<AttributeX509> Attributes => CollectionUtilities.Proxy(m_attributes);
	}
}
