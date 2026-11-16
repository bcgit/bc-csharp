using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
    * Some other restriction regarding the usage of this certificate.
    * <p/>
    * <pre>
    *  RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
    * </pre>
    */
    public class Restriction
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Restriction"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Restriction"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Restriction"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Restriction GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Restriction restriction)
                return restriction;
            return new Restriction(DirectoryString.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Restriction"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Restriction"/>.</returns>
        public static Restriction GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Restriction(DirectoryString.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Restriction"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Restriction"/>.</returns>
        public static Restriction GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Restriction(DirectoryString.GetTagged(taggedObject, declaredExplicit));

        private readonly DirectoryString m_restriction;

        /**
        * Constructor from DirectoryString.
        * <p/>
        * The DirectoryString is of type RestrictionSyntax:
        * <p/>
        * <pre>
        *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
        * </pre>
        *
        * @param restriction A IAsn1String.
        */
        private Restriction(DirectoryString restriction)
        {
            m_restriction = restriction;
        }

        /**
        * Constructor from a given details.
        *
        * @param restriction The description of the restriction.
        */
        public Restriction(string restriction)
        {
            m_restriction = new DirectoryString(restriction);
        }

        /// <summary>Gets the restriction string.</summary>
        public virtual DirectoryString RestrictionString => m_restriction;

        /**
        * Produce an object suitable for an Asn1OutputStream.
        * <p/>
        * Returns:
        * <p/>
        * <pre>
        *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
        * <p/>
        * </pre>
        *
        * @return an Asn1Object
        */
        public override Asn1Object ToAsn1Object() => m_restriction.ToAsn1Object();
    }
}
