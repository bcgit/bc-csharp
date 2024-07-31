using System;
using System.Diagnostics;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
	* Attribute to indicate that the certificate holder may sign in the name of a
	* third person.
	* <p>
	* ISIS-MTT PROFILE: The corresponding ProcurationSyntax contains either the
	* name of the person who is represented (subcomponent thirdPerson) or a
	* reference to his/her base certificate (in the component signingFor,
	* subcomponent certRef), furthermore the optional components country and
	* typeSubstitution to indicate the country whose laws apply, and respectively
	* the type of procuration (e.g. manager, procuration, custody).
	* </p>
	* <p>
	* ISIS-MTT PROFILE: The GeneralName MUST be of type directoryName and MAY only
	* contain: - RFC3039 attributes, except pseudonym (countryName, commonName,
	* surname, givenName, serialNumber, organizationName, organizationalUnitName,
	* stateOrProvincename, localityName, postalAddress) and - SubjectDirectoryName
	* attributes (title, dateOfBirth, placeOfBirth, gender, countryOfCitizenship,
	* countryOfResidence and NameAtBirth).
	* </p>
	* <pre>
	*               ProcurationSyntax ::= SEQUENCE {
	*                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
	*                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
	*                 signingFor [3] EXPLICIT SigningFor 
	*               }
	*               
	*               SigningFor ::= CHOICE 
	*               { 
	*                 thirdPerson GeneralName,
	*                 certRef IssuerSerial 
	*               }
	* </pre>
	* 
	*/
    public class ProcurationSyntax
		: Asn1Encodable
	{
        public static ProcurationSyntax GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ProcurationSyntax procurationSyntax)
                return procurationSyntax;
            return new ProcurationSyntax(Asn1Sequence.GetInstance(obj));
        }

        public static ProcurationSyntax GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ProcurationSyntax(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ProcurationSyntax GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ProcurationSyntax(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerPrintableString m_country;
        private readonly DirectoryString m_typeOfSubstitution;
		private readonly Asn1Encodable m_signingFor;

        /**
		* Constructor from Asn1Sequence.
		* <p/>
		* The sequence is of type ProcurationSyntax:
		* <p/>
		* <pre>
		*               ProcurationSyntax ::= SEQUENCE {
		*                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
		*                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
		*                 signingFor [3] EXPLICIT SigningFor
		*               }
		* <p/>
		*               SigningFor ::= CHOICE
		*               {
		*                 thirdPerson GeneralName,
		*                 certRef IssuerSerial
		*               }
		* </pre>
		*
		* @param seq The ASN.1 sequence.
		*/
        private ProcurationSyntax(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_country = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, DerPrintableString.GetTagged);
            m_typeOfSubstitution = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, DirectoryString.GetTagged);
            m_signingFor = Asn1Utilities.ReadContextTagged(seq, ref pos, 3, true, GetTaggedSigningFor);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        /**
		* Constructor from a given details.
		* <p/>
		* <p/>
		* Either <code>generalName</code> or <code>certRef</code> MUST be
		* <code>null</code>.
		*
		* @param country            The country code whose laws apply.
		* @param typeOfSubstitution The type of procuration.
		* @param certRef            Reference to certificate of the person who is represented.
		*/
        public ProcurationSyntax(string country, DirectoryString typeOfSubstitution, IssuerSerial certRef)
        {
            m_country = country == null ? null : new DerPrintableString(country, true);
			m_typeOfSubstitution = typeOfSubstitution;
			m_signingFor = certRef ?? throw new ArgumentNullException(nameof(certRef));
		}

        /**
		 * Constructor from a given details.
		 * <p/>
		 * <p/>
		 * Either <code>generalName</code> or <code>certRef</code> MUST be
		 * <code>null</code>.
		 *
		 * @param country            The country code whose laws apply.
		 * @param typeOfSubstitution The type of procuration.
		 * @param thirdPerson        The GeneralName of the person who is represented.
		 */
        public ProcurationSyntax(string country, DirectoryString typeOfSubstitution, GeneralName thirdPerson)
        {
            m_country = country == null ? null : new DerPrintableString(country, true);
            m_typeOfSubstitution = typeOfSubstitution;
            m_signingFor = thirdPerson ?? throw new ArgumentNullException(nameof(thirdPerson));
		}

		public virtual string Country => m_country?.GetString();

		public virtual DirectoryString TypeOfSubstitution => m_typeOfSubstitution;

		public virtual GeneralName ThirdPerson => m_signingFor as GeneralName;

		public virtual IssuerSerial CertRef => m_signingFor as IssuerSerial;

		/**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*               ProcurationSyntax ::= SEQUENCE {
		*                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
		*                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
		*                 signingFor [3] EXPLICIT SigningFor
		*               }
		* <p/>
		*               SigningFor ::= CHOICE
		*               {
		*                 thirdPerson GeneralName,
		*                 certRef IssuerSerial
		*               }
		* </pre>
		*
		* @return an Asn1Object
		*/
		public override Asn1Object ToAsn1Object()
		{
            Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.AddOptionalTagged(true, 1, m_country);
            v.AddOptionalTagged(true, 2, m_typeOfSubstitution);
			v.Add(new DerTaggedObject(true, 3, m_signingFor));
            return new DerSequence(v);
		}

        private static Asn1Encodable GetInstanceSigningFor(Asn1Encodable obj)
        {
			var generalName = GeneralName.GetOptional(obj);
			if (generalName != null)
				return generalName;

			var issuerSerial = IssuerSerial.GetOptional(obj);
			if (issuerSerial != null)
				return issuerSerial;

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

		private static Asn1Encodable GetTaggedSigningFor(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
			Debug.Assert(taggedObject != null);
			Debug.Assert(declaredExplicit);

            return GetInstanceSigningFor(taggedObject.GetExplicitBaseObject());
        }
    }
}
