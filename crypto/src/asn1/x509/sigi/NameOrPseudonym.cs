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
        /// <summary>Return an <see cref="NameOrPseudonym"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="NameOrPseudonym"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="NameOrPseudonym"/>, or null if <paramref name="obj"/> is null.</returns>
        public static NameOrPseudonym GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="NameOrPseudonym"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="NameOrPseudonym"/>.</returns>
        public static NameOrPseudonym GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="NameOrPseudonym"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="NameOrPseudonym"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="NameOrPseudonym"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="NameOrPseudonym"/>.</returns>
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
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_surname = Asn1Utilities.Read(seq, ref pos, DirectoryString.GetInstance);
            m_givenName = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
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

        /// <summary>Gets the pseudonym.</summary>
        public DirectoryString Pseudonym => m_pseudonym;

        /// <summary>Gets the surname.</summary>
        public DirectoryString Surname => m_surname;

        /// <summary>Return the given name.</summary>
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
