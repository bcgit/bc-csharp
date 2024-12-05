namespace Org.BouncyCastle.Asn1.X509
{
    // TODO[api] Make static
    public abstract class X509ObjectIdentifiers
    {
        //
        // base id
        //
        public static readonly DerObjectIdentifier attributeType = new DerObjectIdentifier("2.5.4");

        public static readonly DerObjectIdentifier CommonName = attributeType.Branch("3");
        public static readonly DerObjectIdentifier CountryName = attributeType.Branch("6");
        public static readonly DerObjectIdentifier LocalityName = attributeType.Branch("7");
        public static readonly DerObjectIdentifier StateOrProvinceName = attributeType.Branch("8");
        public static readonly DerObjectIdentifier Organization = attributeType.Branch("10");
        public static readonly DerObjectIdentifier OrganizationalUnitName = attributeType.Branch("11");

        public static readonly DerObjectIdentifier id_at_telephoneNumber = attributeType.Branch("20");
        public static readonly DerObjectIdentifier id_at_name = attributeType.Branch("41");
        public static readonly DerObjectIdentifier id_at_organizationIdentifier = attributeType.Branch("97");

        // id-SHA1 OBJECT IDENTIFIER ::=
        //   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }    //
        public static readonly DerObjectIdentifier IdSha1 = new DerObjectIdentifier("1.3.14.3.2.26");

		//
        // ripemd160 OBJECT IDENTIFIER ::=
        //      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) hashAlgorithm(2) RipeMD-160(1)}
        //
        public static readonly DerObjectIdentifier RipeMD160 = new DerObjectIdentifier("1.3.36.3.2.1");

		//
        // ripemd160WithRSAEncryption OBJECT IDENTIFIER ::=
        //      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) signatureAlgorithm(3) rsaSignature(1) rsaSignatureWithripemd160(2) }
        //
        public static readonly DerObjectIdentifier RipeMD160WithRsaEncryption = new DerObjectIdentifier("1.3.36.3.3.1.2");

		public static readonly DerObjectIdentifier IdEARsa = new DerObjectIdentifier("2.5.8.1.1");

		// id-pkix
		public static readonly DerObjectIdentifier IdPkix = new DerObjectIdentifier("1.3.6.1.5.5.7");

		//
		// private internet extensions
		//
		public static readonly DerObjectIdentifier IdPE = IdPkix.Branch("1");

        /** 1.3.6.1.5.5.7.6 */
        public static readonly DerObjectIdentifier pkix_algorithms = IdPkix.Branch("6");

        /**
         *    id-RSASSA-PSS-SHAKE128  OBJECT IDENTIFIER  ::=  { iso(1)
         *             identified-organization(3) dod(6) internet(1)
         *             security(5) mechanisms(5) pkix(7) algorithms(6) 30 }
         */
        public static readonly DerObjectIdentifier id_RSASSA_PSS_SHAKE128 = pkix_algorithms.Branch("30");

        /**
         *    id-RSASSA-PSS-SHAKE256  OBJECT IDENTIFIER  ::=  { iso(1)
         *             identified-organization(3) dod(6) internet(1)
         *             security(5) mechanisms(5) pkix(7) algorithms(6) 31 }
         */
        public static readonly DerObjectIdentifier id_RSASSA_PSS_SHAKE256 = pkix_algorithms.Branch("31");

        /**
         * id-ecdsa-with-shake128 OBJECT IDENTIFIER  ::=  { iso(1)
         *        identified-organization(3) dod(6) internet(1)
         *        security(5) mechanisms(5) pkix(7) algorithms(6) 32 }
         */
        public static readonly DerObjectIdentifier id_ecdsa_with_shake128 = pkix_algorithms.Branch("32");

        /**
         * id-ecdsa-with-shake256 OBJECT IDENTIFIER  ::=  { iso(1)
         *         identified-organization(3) dod(6) internet(1)
         *         security(5) mechanisms(5) pkix(7) algorithms(6) 33 }
         */
        public static readonly DerObjectIdentifier id_ecdsa_with_shake256 = pkix_algorithms.Branch("33");

        public static readonly DerObjectIdentifier id_pda = IdPkix.Branch("9");

        //
        // authority information access
        //
        public static readonly DerObjectIdentifier IdAD = IdPkix.Branch("48");
        public static readonly DerObjectIdentifier IdADOcsp = IdAD.Branch("1");
        public static readonly DerObjectIdentifier IdADCAIssuers = IdAD.Branch("2");

		//
		// OID for ocsp and crl uri in AuthorityInformationAccess extension
		//
		public static readonly DerObjectIdentifier OcspAccessMethod = IdADOcsp;
		public static readonly DerObjectIdentifier CrlAccessMethod = IdADCAIssuers;

        public static readonly DerObjectIdentifier id_ce = new DerObjectIdentifier("2.5.29");
    }
}
