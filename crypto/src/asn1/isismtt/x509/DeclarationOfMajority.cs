using System;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
     * A declaration of majority.
     * <p/>
     * <pre>
     *           DeclarationOfMajoritySyntax ::= CHOICE
     *           {
     *             notYoungerThan [0] IMPLICIT INTEGER,
     *             fullAgeAtCountry [1] IMPLICIT SEQUENCE
     *             {
     *               fullAge BOOLEAN DEFAULT TRUE,
     *               country PrintableString (SIZE(2))
     *             }
     *             dateOfBirth [2] IMPLICIT GeneralizedTime
     *           }
     * </pre>
     * <p/>
     * fullAgeAtCountry indicates the majority of the owner with respect to the laws
     * of a specific country.
     */
    public class DeclarationOfMajority
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>A choice type, holding the alternative that was selected.</summary>
        public enum Choice
        {
            NotYoungerThan = 0,
            FullAgeAtCountry = 1,
            DateOfBirth = 2
        };

        /// <summary>Return an <see cref="DeclarationOfMajority"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DeclarationOfMajority"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DeclarationOfMajority"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DeclarationOfMajority GetInstance(object obj) =>
            Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="DeclarationOfMajority"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DeclarationOfMajority"/>.</returns>
        public static DeclarationOfMajority GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="DeclarationOfMajority"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="DeclarationOfMajority"/>, or null if <paramref name="element"/> is null.</returns>
        public static DeclarationOfMajority GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DeclarationOfMajority declarationOfMajority)
                return declarationOfMajority;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new DeclarationOfMajority(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        /// <summary>Return an <see cref="DeclarationOfMajority"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DeclarationOfMajority"/>.</returns>
        public static DeclarationOfMajority GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case (int)Choice.NotYoungerThan:
                    return DerInteger.GetTagged(taggedObject, false);
                case (int)Choice.FullAgeAtCountry:
                    // TODO Add type for fullAgeAtCountry?
                    return Asn1Sequence.GetTagged(taggedObject, false);
                case (int)Choice.DateOfBirth:
                    return Asn1GeneralizedTime.GetTagged(taggedObject, false);
                }
            }

            return null;
        }

        private readonly int m_tag;
        private readonly Asn1Encodable m_baseObject;

        private DeclarationOfMajority(int tag, Asn1Encodable baseObject)
        {
            m_tag = tag;
            m_baseObject = baseObject;
        }

        /// <summary>Create a new <see cref="DeclarationOfMajority"/>.</summary>
        /// <param name="notYoungerThan">The not younger than.</param>
        public DeclarationOfMajority(int notYoungerThan)
        {
            m_tag = (int)Choice.NotYoungerThan;
            m_baseObject = DerInteger.ValueOf(notYoungerThan);
        }

        /// <summary>Create a new <see cref="DeclarationOfMajority"/>.</summary>
        /// <param name="fullAge">true if full age, false otherwise.</param>
        /// <param name="country">The country.</param>
        public DeclarationOfMajority(bool fullAge, string country)
        {
            if (country.Length != 2)
                throw new ArgumentException("country can only be 2 characters", nameof(country));

            DerPrintableString countryString = new DerPrintableString(country, true);

            DerSequence seq;
            if (fullAge)
            {
                seq = new DerSequence(countryString);
            }
            else
            {
                seq = new DerSequence(DerBoolean.False, countryString);
            }

            m_tag = (int)Choice.FullAgeAtCountry;
            m_baseObject = seq;
        }

        /// <summary>Create a new <see cref="DeclarationOfMajority"/>.</summary>
        /// <param name="dateOfBirth">The date of birth.</param>
        public DeclarationOfMajority(Asn1GeneralizedTime dateOfBirth)
        {
            m_tag = (int)Choice.DateOfBirth;
            m_baseObject = dateOfBirth ?? throw new ArgumentNullException(nameof(dateOfBirth));
        }

        /// <summary>Gets the type.</summary>
        public Choice Type => (Choice)m_tag;

        /**
         * @return notYoungerThan if that's what we are, -1 otherwise
         */
        public virtual int NotYoungerThan
        {
            get
            {
                switch (Type)
                {
                case Choice.NotYoungerThan:
                    return DerInteger.GetInstance(m_baseObject).IntValueExact;
                default:
                    return -1;
                }
            }
        }

        /// <summary>Gets the full age at country.</summary>
        public virtual Asn1Sequence FullAgeAtCountry
        {
            get
            {
                switch (Type)
                {
                case Choice.FullAgeAtCountry:
                    return Asn1Sequence.GetInstance(m_baseObject);
                default:
                    return null;
                }
            }
        }

        /// <summary>Gets the date of birth.</summary>
        public virtual Asn1GeneralizedTime DateOfBirth
        {
            get
            {
                switch (Type)
                {
                case Choice.DateOfBirth:
                    return Asn1GeneralizedTime.GetInstance(m_baseObject);
                default:
                    return null;
                }
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <p/>
         * Returns:
         * <p/>
         * <pre>
         *           DeclarationOfMajoritySyntax ::= CHOICE
         *           {
         *             notYoungerThan [0] IMPLICIT INTEGER,
         *             fullAgeAtCountry [1] IMPLICIT SEQUENCE
         *             {
         *               fullAge BOOLEAN DEFAULT TRUE,
         *               country PrintableString (SIZE(2))
         *             }
         *             dateOfBirth [2] IMPLICIT GeneralizedTime
         *           }
         * </pre>
         *
         * @return an Asn1Object
         */
        public override Asn1Object ToAsn1Object() => new DerTaggedObject(false, m_tag, m_baseObject);
    }
}
