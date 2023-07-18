using System;

using Org.BouncyCastle.Utilities;

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
		public enum Choice
		{
			NotYoungerThan = 0,
			FullAgeAtCountry = 1,
			DateOfBirth = 2
		};

		private readonly Asn1TaggedObject m_declaration;

		public DeclarationOfMajority(int notYoungerThan)
		{
			m_declaration = new DerTaggedObject(false, 0, new DerInteger(notYoungerThan));
		}

		public DeclarationOfMajority(bool fullAge, string country)
		{
			if (country.Length > 2)
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

			m_declaration = new DerTaggedObject(false, 1, seq);
		}

		public DeclarationOfMajority(Asn1GeneralizedTime dateOfBirth)
		{
			m_declaration = new DerTaggedObject(false, 2, dateOfBirth);
		}

		public static DeclarationOfMajority GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is DeclarationOfMajority declarationOfMajority)
				return declarationOfMajority;

			if (obj is Asn1TaggedObject taggedObject)
				return new DeclarationOfMajority(Asn1Utilities.CheckTagClass(taggedObject, Asn1Tags.ContextSpecific));

            throw new ArgumentException("unknown object in factory: " + Platform.GetTypeName(obj), nameof(obj));
		}

		private DeclarationOfMajority(Asn1TaggedObject o)
		{
			if (o.TagNo > 2)
				throw new ArgumentException("Bad tag number: " + o.TagNo);

			m_declaration = o;
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
		public override Asn1Object ToAsn1Object()
		{
			return m_declaration;
		}

		public Choice Type
		{
			get { return (Choice)m_declaration.TagNo; }
		}

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
                    return DerInteger.GetInstance(m_declaration, false).IntValueExact;
				default:
					return -1;
				}
			}
		}

		public virtual Asn1Sequence FullAgeAtCountry
		{
			get
			{
				switch (Type)
				{
				case Choice.FullAgeAtCountry:
					return Asn1Sequence.GetInstance(m_declaration, false);
				default:
					return null;
				}
			}
		}

		public virtual Asn1GeneralizedTime DateOfBirth
		{
			get
			{
				switch (Type)
				{
				case Choice.DateOfBirth:
					return Asn1GeneralizedTime.GetInstance(m_declaration, false);
				default:
					return null;
				}
			}
		}
	}
}
