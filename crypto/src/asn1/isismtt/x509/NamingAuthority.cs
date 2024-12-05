using System;

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
	* Names of authorities which are responsible for the administration of title
	* registers.
	* 
	* <pre>
	*             NamingAuthority ::= SEQUENCE 
	*             {
	*               namingAuthorityID OBJECT IDENTIFIER OPTIONAL,
	*               namingAuthorityUrl IA5String OPTIONAL,
	*               namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
	*             }
	* </pre>
	* @see Org.BouncyCastle.Asn1.IsisMtt.X509.AdmissionSyntax
	* 
	*/
    public class NamingAuthority
		: Asn1Encodable
	{
		/**
		* Profession OIDs should always be defined under the OID branch of the
		* responsible naming authority. At the time of this writing, the work group
		* �Recht, Wirtschaft, Steuern� (�Law, Economy, Taxes�) is registered as the
		* first naming authority under the OID id-isismtt-at-namingAuthorities.
		*/
		public static readonly DerObjectIdentifier IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern =
			IsisMttObjectIdentifiers.IdIsisMttATNamingAuthorities.Branch("1");

		public static NamingAuthority GetInstance(object obj)
		{
            if (obj == null)
                return null;
            if (obj is NamingAuthority namingAuthority)
                return namingAuthority;
            return new NamingAuthority(Asn1Sequence.GetInstance(obj));
		}

		public static NamingAuthority GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
			new NamingAuthority(Asn1Sequence.GetInstance(obj, isExplicit));

        public static NamingAuthority GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new NamingAuthority(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_namingAuthorityID;
        private readonly DerIA5String m_namingAuthorityUrl;
        private readonly DirectoryString m_namingAuthorityText;

        /**
		* Constructor from Asn1Sequence.
		* <p/>
		* <p/>
		* <pre>
		*             NamingAuthority ::= SEQUENCE
		*             {
		*               namingAuthorityID OBJECT IDENTIFIER OPTIONAL,
		*               namingAuthorityUrl IA5String OPTIONAL,
		*               namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		*             }
		* </pre>
		*
		* @param seq The ASN.1 sequence.
		*/
        private NamingAuthority(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_namingAuthorityID = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);
            m_namingAuthorityUrl = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);
            m_namingAuthorityText = Asn1Utilities.ReadOptional(seq, ref pos, DirectoryString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		/**
		* @return Returns the namingAuthorityID.
		*/
		public virtual DerObjectIdentifier NamingAuthorityID => m_namingAuthorityID;

		/**
		* @return Returns the namingAuthorityText.
		*/
		public virtual DirectoryString NamingAuthorityText => m_namingAuthorityText;

		/**
		* @return Returns the namingAuthorityUrl.
		*/
		public virtual string NamingAuthorityUrl => m_namingAuthorityUrl?.GetString();

        public virtual DerIA5String NamingAuthorityUrlData => m_namingAuthorityUrl;

        /**
		* Constructor from given details.
		* <p/>
		* All parameters can be combined.
		*
		* @param namingAuthorityID   ObjectIdentifier for naming authority.
		* @param namingAuthorityUrl  URL for naming authority.
		* @param namingAuthorityText Textual representation of naming authority.
		*/
        public NamingAuthority(DerObjectIdentifier namingAuthorityID, string namingAuthorityUrl,
			DirectoryString namingAuthorityText)
        {
            m_namingAuthorityID = namingAuthorityID;
            m_namingAuthorityUrl = namingAuthorityUrl == null ? null : new DerIA5String(namingAuthorityUrl, true);
            m_namingAuthorityText = namingAuthorityText;
        }

        /**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*             NamingAuthority ::= SEQUENCE
		*             {
		*               namingAuthorityID OBJECT IDENTIFIER OPTIONAL,
		*               namingAuthorityUrl IA5String OPTIONAL,
		*               namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		*             }
		* </pre>
		*
		* @return an Asn1Object
		*/
        public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptional(m_namingAuthorityID);
            v.AddOptional(m_namingAuthorityUrl);
            v.AddOptional(m_namingAuthorityText);
			return new DerSequence(v);
		}
	}
}
