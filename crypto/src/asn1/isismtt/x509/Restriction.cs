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
        public static Restriction GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Restriction restriction)
                return restriction;
            return new Restriction(DirectoryString.GetInstance(obj));
        }

        public static Restriction GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Restriction(DirectoryString.GetInstance(taggedObject, declaredExplicit));

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
