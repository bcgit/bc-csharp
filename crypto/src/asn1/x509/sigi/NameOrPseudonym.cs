using System;

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.X509.SigI
{
    /**
	* Structure for a name or pseudonym.
	* 
	* <pre>
	*       NameOrPseudonym ::= CHOICE {
	*     	   surAndGivenName SEQUENCE {
	*     	     surName DirectoryString,
	*     	     givenName SEQUENCE OF DirectoryString 
	*         },
	*     	   pseudonym DirectoryString 
	*       }
	* </pre>
	* 
	* @see Org.BouncyCastle.Asn1.X509.sigi.PersonalData
	* 
	*/
    public class NameOrPseudonym
        : Asn1Encodable, IAsn1Choice
    {
        public static NameOrPseudonym GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static NameOrPseudonym GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static NameOrPseudonym GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is NameOrPseudonym nameOrPseudonym)
                return nameOrPseudonym;

            // TODO Add type for surAndGivenName?
            Asn1Sequence surAndGivenName = Asn1Sequence.GetOptional(element);
            if (surAndGivenName != null)
                return new NameOrPseudonym(surAndGivenName);

            DirectoryString pseudonym = DirectoryString.GetOptional(element);
            if (pseudonym != null)
                return new NameOrPseudonym(pseudonym);

            return null;
        }

        public static NameOrPseudonym GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly DirectoryString m_pseudonym;
        private readonly DirectoryString m_surname;
        private readonly Asn1Sequence m_givenName;

        /**
         * Constructor from DERString.
         * <p/>
         * The sequence is of type NameOrPseudonym:
         * <p/>
         * <pre>
         *       NameOrPseudonym ::= CHOICE {
         *     	   surAndGivenName SEQUENCE {
         *     	     surName DirectoryString,
         *     	     givenName SEQUENCE OF DirectoryString
         *         },
         *     	   pseudonym DirectoryString
         *       }
         * </pre>
         * @param pseudonym pseudonym value to use.
         */
        public NameOrPseudonym(DirectoryString pseudonym)
        {
            m_pseudonym = pseudonym ?? throw new ArgumentNullException(nameof(pseudonym));
        }

        /**
         * Constructor from Asn1Sequence.
         * <p/>
         * The sequence is of type NameOrPseudonym:
         * <p/>
         * <pre>
         *       NameOrPseudonym ::= CHOICE {
         *     	   surAndGivenName SEQUENCE {
         *     	     surName DirectoryString,
         *     	     givenName SEQUENCE OF DirectoryString
         *         },
         *     	   pseudonym DirectoryString
         *       }
         * </pre>
         *
         * @param seq The ASN.1 sequence.
         */
        private NameOrPseudonym(Asn1Sequence seq)
        {
            if (seq.Count != 2)
                throw new ArgumentException("Bad sequence size: " + seq.Count);

            m_surname = DirectoryString.GetInstance(seq[0]);
            m_givenName = Asn1Sequence.GetInstance(seq[1]);
        }

        /**
         * Constructor from a given details.
         *
         * @param pseudonym The pseudonym.
         */
        public NameOrPseudonym(string pseudonym)
            : this(new DirectoryString(pseudonym))
        {
        }

        /**
         * Constructor from a given details.
         *
         * @param surname   The surname.
         * @param givenName A sequence of directory strings making up the givenName
         */
        public NameOrPseudonym(DirectoryString surname, Asn1Sequence givenName)
        {
            m_surname = surname ?? throw new ArgumentNullException(nameof(surname));
            m_givenName = givenName ?? throw new ArgumentNullException(nameof(givenName));
        }

        public DirectoryString Pseudonym => m_pseudonym;

        public DirectoryString Surname => m_surname;

        public DirectoryString[] GetGivenName() => m_givenName?.MapElements(DirectoryString.GetInstance);

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <p/>
         * Returns:
         * <p/>
         * <pre>
         *       NameOrPseudonym ::= CHOICE {
         *     	   surAndGivenName SEQUENCE {
         *     	     surName DirectoryString,
         *     	     givenName SEQUENCE OF DirectoryString
         *         },
         *     	   pseudonym DirectoryString
         *       }
         * </pre>
         *
         * @return an Asn1Object
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_pseudonym != null)
                return m_pseudonym.ToAsn1Object();

            return new DerSequence(m_surname, m_givenName);
        }
    }
}
