using System;

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
	* Professions, specializations, disciplines, fields of activity, etc.
	* 
	* <pre>
	*               ProfessionInfo ::= SEQUENCE 
	*               {
	*                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
	*                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
	*                 professionOids SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
	*                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
	*                 addProfessionInfo OCTET STRING OPTIONAL 
	*               }
	* </pre>
	* 
	* @see Org.BouncyCastle.Asn1.IsisMtt.X509.AdmissionSyntax
	*/
    public class ProfessionInfo
		: Asn1Encodable
	{
		/**
		* Rechtsanw�ltin
		*/
		public static readonly DerObjectIdentifier Rechtsanwltin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("1");

		/**
		* Rechtsanwalt
		*/
		public static readonly DerObjectIdentifier Rechtsanwalt =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("2");

		/**
		* Rechtsbeistand
		*/
		public static readonly DerObjectIdentifier Rechtsbeistand =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("3");

		/**
		* Steuerberaterin
		*/
		public static readonly DerObjectIdentifier Steuerberaterin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("4");

		/**
		* Steuerberater
		*/
		public static readonly DerObjectIdentifier Steuerberater =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("5");

		/**
		* Steuerbevollm�chtigte
		*/
		public static readonly DerObjectIdentifier Steuerbevollmchtigte =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("6");

		/**
		* Steuerbevollm�chtigter
		*/
		public static readonly DerObjectIdentifier Steuerbevollmchtigter =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("7");

		/**
		* Notarin
		*/
		public static readonly DerObjectIdentifier Notarin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("8");

		/**
		* Notar
		*/
		public static readonly DerObjectIdentifier Notar =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("9");

		/**
		* Notarvertreterin
		*/
		public static readonly DerObjectIdentifier Notarvertreterin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("10");

		/**
		* Notarvertreter
		*/
		public static readonly DerObjectIdentifier Notarvertreter =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("11");

		/**
		* Notariatsverwalterin
		*/
		public static readonly DerObjectIdentifier Notariatsverwalterin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("12");

		/**
		* Notariatsverwalter
		*/
		public static readonly DerObjectIdentifier Notariatsverwalter =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("13");

		/**
		* Wirtschaftspr�ferin
		*/
		public static readonly DerObjectIdentifier Wirtschaftsprferin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("14");

		/**
		* Wirtschaftspr�fer
		*/
		public static readonly DerObjectIdentifier Wirtschaftsprfer =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("15");

		/**
		* Vereidigte Buchpr�ferin
		*/
		public static readonly DerObjectIdentifier VereidigteBuchprferin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("16");

		/**
		* Vereidigter Buchpr�fer
		*/
		public static readonly DerObjectIdentifier VereidigterBuchprfer =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("17");

		/**
		* Patentanw�ltin
		*/
		public static readonly DerObjectIdentifier Patentanwltin =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("18");

		/**
		* Patentanwalt
		*/
		public static readonly DerObjectIdentifier Patentanwalt =
			NamingAuthority.IdIsisMttATNamingAuthoritiesRechtWirtschaftSteuern.Branch("19");

        public static ProfessionInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ProfessionInfo professionInfo)
                return professionInfo;
            return new ProfessionInfo(Asn1Sequence.GetInstance(obj));
        }

        public static ProfessionInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ProfessionInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ProfessionInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ProfessionInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly NamingAuthority m_namingAuthority;
        private readonly Asn1Sequence m_professionItems;
        private readonly Asn1Sequence m_professionOids;
        private readonly DerPrintableString m_registrationNumber;
        private readonly Asn1OctetString m_addProfessionInfo;

        /**
		* Constructor from Asn1Sequence.
		* <p/>
		* <p/>
		* <pre>
		*               ProfessionInfo ::= SEQUENCE
		*               {
		*                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		*                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		*                 professionOids SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		*                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		*                 addProfessionInfo OCTET STRING OPTIONAL
		*               }
		* </pre>
		*
		* @param seq The ASN.1 sequence.
		*/
        private ProfessionInfo(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_namingAuthority = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, NamingAuthority.GetTagged);
			m_professionItems = Asn1Sequence.GetInstance(seq[pos++]);
			m_professionOids = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);
            m_registrationNumber = Asn1Utilities.ReadOptional(seq, ref pos, DerPrintableString.GetOptional);
            m_addProfessionInfo = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        /**
		* Constructor from given details.
		* <p/>
		* <code>professionItems</code> is mandatory, all other parameters are
		* optional.
		*
		* @param namingAuthority    The naming authority.
		* @param professionItems    Directory strings of the profession.
		* @param professionOids     DERObjectIdentfier objects for the
		*                           profession.
		* @param registrationNumber Registration number.
		* @param addProfessionInfo  Additional infos in encoded form.
		*/
        public ProfessionInfo(NamingAuthority namingAuthority, DirectoryString[] professionItems,
            DerObjectIdentifier[] professionOids, string registrationNumber, Asn1OctetString addProfessionInfo)
        {
            m_namingAuthority = namingAuthority;
			m_professionItems = DerSequence.FromElements(professionItems);
			m_professionOids = DerSequence.FromElementsOptional(professionOids);
			m_registrationNumber = registrationNumber == null ? null : new DerPrintableString(registrationNumber, true);
			m_addProfessionInfo = addProfessionInfo;
		}

		/**
		* @return Returns the addProfessionInfo.
		*/
		public virtual Asn1OctetString AddProfessionInfo => m_addProfessionInfo;

		/**
		* @return Returns the namingAuthority.
		*/
		public virtual NamingAuthority NamingAuthority => m_namingAuthority;

        /**
		* @return Returns the professionItems.
		*/
        public virtual DirectoryString[] GetProfessionItems() =>
			m_professionItems.MapElements(DirectoryString.GetInstance);

        /**
		* @return Returns the professionOids.
		*/
        public virtual DerObjectIdentifier[] GetProfessionOids() =>
            m_professionOids?.MapElements(DerObjectIdentifier.GetInstance) ?? new DerObjectIdentifier[0];

		/**
		* @return Returns the registrationNumber.
		*/
		public virtual string RegistrationNumber => m_registrationNumber?.GetString();

        /**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*               ProfessionInfo ::= SEQUENCE
		*               {
		*                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		*                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		*                 professionOids SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		*                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		*                 addProfessionInfo OCTET STRING OPTIONAL
		*               }
		* </pre>
		*
		* @return an Asn1Object
		*/
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.AddOptionalTagged(true, 0, m_namingAuthority);
            v.Add(m_professionItems);
            v.AddOptional(m_professionOids);
            v.AddOptional(m_registrationNumber);
            v.AddOptional(m_addProfessionInfo);
            return new DerSequence(v);
        }
	}
}
