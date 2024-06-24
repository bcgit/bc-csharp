using System;

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.Esf
{
    /**
	* Signer-Location attribute (RFC3126).
	*
	* <pre>
	*   SignerLocation ::= SEQUENCE {
	*       countryName        [0] DirectoryString OPTIONAL,
	*       localityName       [1] DirectoryString OPTIONAL,
	*       postalAddress      [2] PostalAddress OPTIONAL }
	*
	*   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
	* </pre>
	*/
    public class SignerLocation
        : Asn1Encodable
    {
        public static SignerLocation GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignerLocation signerLocation)
                return signerLocation;
            return new SignerLocation(Asn1Sequence.GetInstance(obj));
        }

        public static SignerLocation GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new SignerLocation(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DirectoryString m_countryName;
        private readonly DirectoryString m_localityName;
        private readonly Asn1Sequence m_postalAddress;

        public SignerLocation(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_countryName = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DirectoryString.GetTagged);
            m_localityName = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, DirectoryString.GetTagged);

            m_postalAddress = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Asn1Sequence.GetTagged);
            if (m_postalAddress != null)
            {
                if (m_postalAddress.Count > 6)
                    throw new ArgumentException("postal address must contain less than 6 strings");

                m_postalAddress.MapElements(element => DirectoryString.GetInstance(element.ToAsn1Object()));
            }

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        private SignerLocation(DirectoryString countryName, DirectoryString localityName, Asn1Sequence postalAddress)
        {
            if (postalAddress != null && postalAddress.Count > 6)
                throw new ArgumentException("postal address must contain less than 6 strings");

            m_countryName = countryName;
            m_localityName = localityName;
            m_postalAddress = postalAddress;
        }

        public SignerLocation(DirectoryString countryName, DirectoryString localityName, DirectoryString[] postalAddress)
            : this(countryName, localityName, new DerSequence(postalAddress))
        {
        }

        public SignerLocation(DerUtf8String countryName, DerUtf8String localityName, Asn1Sequence postalAddress)
            : this(DirectoryString.GetInstance(countryName), DirectoryString.GetInstance(localityName), postalAddress)
        {
        }

        public DirectoryString Country => m_countryName;

        public DirectoryString Locality => m_localityName;

        public DirectoryString[] GetPostal() =>
            m_postalAddress?.MapElements(element => DirectoryString.GetInstance(element.ToAsn1Object()));

        public Asn1Sequence PostalAddress => m_postalAddress;

        /**
		* <pre>
		*   SignerLocation ::= SEQUENCE {
		*       countryName        [0] DirectoryString OPTIONAL,
		*       localityName       [1] DirectoryString OPTIONAL,
		*       postalAddress      [2] PostalAddress OPTIONAL }
		*
		*   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
		*
		*   DirectoryString ::= CHOICE {
		*         teletexString           TeletexString (SIZE (1..MAX)),
		*         printableString         PrintableString (SIZE (1..MAX)),
		*         universalString         UniversalString (SIZE (1..MAX)),
		*         utf8String              UTF8String (SIZE (1.. MAX)),
		*         bmpString               BMPString (SIZE (1..MAX)) }
		* </pre>
		*/
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_countryName);
            v.AddOptionalTagged(true, 1, m_localityName);
            v.AddOptionalTagged(true, 2, m_postalAddress);
            return DerSequence.FromVector(v);
        }
    }
}
