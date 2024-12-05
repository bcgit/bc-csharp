using System;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509.SigI
{
    /**
	* Contains personal data for the otherName field in the subjectAltNames
	* extension.
	* <p/>
	* <pre>
	*     PersonalData ::= SEQUENCE {
	*       nameOrPseudonym NameOrPseudonym,
	*       nameDistinguisher [0] INTEGER OPTIONAL,
	*       dateOfBirth [1] GeneralizedTime OPTIONAL,
	*       placeOfBirth [2] DirectoryString OPTIONAL,
	*       gender [3] PrintableString OPTIONAL,
	*       postalAddress [4] DirectoryString OPTIONAL
	*       }
	* </pre>
	*
	* @see Org.BouncyCastle.Asn1.X509.sigi.NameOrPseudonym
	* @see Org.BouncyCastle.Asn1.X509.sigi.SigIObjectIdentifiers
	*/
    public class PersonalData
		: Asn1Encodable
	{
        public static PersonalData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PersonalData personalData)
                return personalData;
            return new PersonalData(Asn1Sequence.GetInstance(obj));
        }

        public static PersonalData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PersonalData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PersonalData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PersonalData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly NameOrPseudonym m_nameOrPseudonym;
        private readonly DerInteger m_nameDistinguisher;
        private readonly Asn1GeneralizedTime m_dateOfBirth;
        private readonly DirectoryString m_placeOfBirth;
        private readonly DerPrintableString m_gender;
        private readonly DirectoryString m_postalAddress;

		/**
		* Constructor from Asn1Sequence.
		* <p/>
		* The sequence is of type NameOrPseudonym:
		* <p/>
		* <pre>
		*     PersonalData ::= SEQUENCE {
		*       nameOrPseudonym NameOrPseudonym,
		*       nameDistinguisher [0] INTEGER OPTIONAL,
		*       dateOfBirth [1] GeneralizedTime OPTIONAL,
		*       placeOfBirth [2] DirectoryString OPTIONAL,
		*       gender [3] PrintableString OPTIONAL,
		*       postalAddress [4] DirectoryString OPTIONAL
		*       }
		* </pre>
		*
		* @param seq The ASN.1 sequence.
		*/
		private PersonalData(Asn1Sequence seq)
		{
			int count = seq.Count, pos = 0;
			if (count < 1 || count > 6)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_nameOrPseudonym = NameOrPseudonym.GetInstance(seq[pos++]);
			m_nameDistinguisher = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, DerInteger.GetTagged);
            m_dateOfBirth = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1GeneralizedTime.GetTagged);
            m_placeOfBirth = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, DirectoryString.GetTagged); //CHOICE
            m_gender = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, false, DerPrintableString.GetTagged);
            m_postalAddress = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, true, DirectoryString.GetTagged); //CHOICE

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        /**
		* Constructor from a given details.
		*
		* @param nameOrPseudonym  Name or pseudonym.
		* @param nameDistinguisher Name distinguisher.
		* @param dateOfBirth      Date of birth.
		* @param placeOfBirth     Place of birth.
		* @param gender           Gender.
		* @param postalAddress    Postal Address.
		*/
        public PersonalData(NameOrPseudonym nameOrPseudonym, BigInteger nameDistinguisher,
			Asn1GeneralizedTime dateOfBirth, DirectoryString placeOfBirth, string gender,
			DirectoryString postalAddress)
        {
            m_nameOrPseudonym = nameOrPseudonym ?? throw new ArgumentNullException(nameof(nameOrPseudonym));
            m_nameDistinguisher = nameDistinguisher == null ? null : new DerInteger(nameDistinguisher);
            m_dateOfBirth = dateOfBirth;
            m_placeOfBirth = placeOfBirth;
            m_gender = gender == null ? null : new DerPrintableString(gender, true);
            m_postalAddress = postalAddress;
        }

        public NameOrPseudonym NameOrPseudonym => m_nameOrPseudonym;

		public BigInteger NameDistinguisher => m_nameDistinguisher?.Value;

		public Asn1GeneralizedTime DateOfBirth => m_dateOfBirth;

		public DirectoryString PlaceOfBirth => m_placeOfBirth;

		public string Gender => m_gender?.GetString();

		public DirectoryString PostalAddress => m_postalAddress;

        /**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*     PersonalData ::= SEQUENCE {
		*       nameOrPseudonym NameOrPseudonym,
		*       nameDistinguisher [0] INTEGER OPTIONAL,
		*       dateOfBirth [1] GeneralizedTime OPTIONAL,
		*       placeOfBirth [2] DirectoryString OPTIONAL,
		*       gender [3] PrintableString OPTIONAL,
		*       postalAddress [4] DirectoryString OPTIONAL
		*       }
		* </pre>
		*
		* @return an Asn1Object
		*/
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);
            v.Add(m_nameOrPseudonym);
            v.AddOptionalTagged(false, 0, m_nameDistinguisher);
            v.AddOptionalTagged(false, 1, m_dateOfBirth);
            v.AddOptionalTagged(true, 2, m_placeOfBirth); // CHOICE
            v.AddOptionalTagged(false, 3, m_gender);
            v.AddOptionalTagged(true, 4, m_postalAddress); // CHOICE
            return new DerSequence(v);
        }
    }
}
