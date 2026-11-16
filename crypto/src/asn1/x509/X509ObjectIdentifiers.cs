namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>Object identifiers for X.509 (RFC 5280 and related standards).</summary>
    // TODO[api] Make static
    public abstract class X509ObjectIdentifiers
    {
        /// <summary>The object identifier <c>2.5.4</c>.</summary>
        //
        // base id
        //
        public static readonly DerObjectIdentifier attributeType = new DerObjectIdentifier("2.5.4");

        /// <summary>The object identifier <c>2.5.4.3</c>.</summary>
        public static readonly DerObjectIdentifier CommonName = attributeType.Branch("3");
        /// <summary>The object identifier <c>2.5.4.6</c>.</summary>
        public static readonly DerObjectIdentifier CountryName = attributeType.Branch("6");
        /// <summary>The object identifier <c>2.5.4.7</c>.</summary>
        public static readonly DerObjectIdentifier LocalityName = attributeType.Branch("7");
        /// <summary>The object identifier <c>2.5.4.8</c>.</summary>
        public static readonly DerObjectIdentifier StateOrProvinceName = attributeType.Branch("8");
        /// <summary>The object identifier <c>2.5.4.10</c>.</summary>
        public static readonly DerObjectIdentifier Organization = attributeType.Branch("10");
        /// <summary>The object identifier <c>2.5.4.11</c>.</summary>
        public static readonly DerObjectIdentifier OrganizationalUnitName = attributeType.Branch("11");

        /// <summary>The object identifier <c>2.5.4.20</c>.</summary>
        public static readonly DerObjectIdentifier id_at_telephoneNumber = attributeType.Branch("20");
        /// <summary>The object identifier <c>2.5.4.41</c>.</summary>
        public static readonly DerObjectIdentifier id_at_name = attributeType.Branch("41");
        /// <summary>The object identifier <c>2.5.4.97</c>.</summary>
        public static readonly DerObjectIdentifier id_at_organizationIdentifier = attributeType.Branch("97");

        /// <summary>The object identifier <c>1.3.14.3.2.26</c>.</summary>
        // id-SHA1 OBJECT IDENTIFIER ::=
        //   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }    //
        public static readonly DerObjectIdentifier IdSha1 = new DerObjectIdentifier("1.3.14.3.2.26");

        /// <summary>The object identifier <c>1.3.36.3.2.1</c>.</summary>
        //
        // ripemd160 OBJECT IDENTIFIER ::=
        //      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) hashAlgorithm(2) RipeMD-160(1)}
        //
        public static readonly DerObjectIdentifier RipeMD160 = new DerObjectIdentifier("1.3.36.3.2.1");

        /// <summary>The object identifier <c>1.3.36.3.3.1.2</c>.</summary>
        //
        // ripemd160WithRSAEncryption OBJECT IDENTIFIER ::=
        //      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) signatureAlgorithm(3) rsaSignature(1) rsaSignatureWithripemd160(2) }
        //
        public static readonly DerObjectIdentifier RipeMD160WithRsaEncryption = new DerObjectIdentifier("1.3.36.3.3.1.2");

        /// <summary>The object identifier <c>2.5.8.1.1</c>.</summary>
        public static readonly DerObjectIdentifier IdEARsa = new DerObjectIdentifier("2.5.8.1.1");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7</c>.</summary>
        // id-pkix
        public static readonly DerObjectIdentifier IdPkix = new DerObjectIdentifier("1.3.6.1.5.5.7");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.1</c>.</summary>
        //
        // private internet extensions
        //
        public static readonly DerObjectIdentifier IdPE = IdPkix.Branch("1");

        /**
         * id-pe-relatedCert OBJECT IDENTIFIER ::= { iso(1)
         *        identified-organization(3) dod(6) internet(1)
         *        security(5) mechanisms(5) pkix(7) pe(1) 36 }
         * <p>
         * Per RFC 9763 sec. 3, the {@code RelatedCertificate} certificate
         * extension. The extension MUST
         * appear in an end-entity certificate only, SHOULD NOT be marked critical,
         * and carries a digest of one previously-issued certificate (the "related
         * certificate") that the CA is asserting belongs to the same end entity —
         * the mechanism that lets a verifier link a classical and a post-quantum
         * certificate during hybrid PQ migration without requiring composite
         * signature algorithms.
         * </p>
         */
        public static readonly DerObjectIdentifier id_pe_relatedCert = IdPE.Branch("36");

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

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.2</c>.</summary>
        public static readonly DerObjectIdentifier id_alg_noSignature = pkix_algorithms.Branch("2");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.36</c>.</summary>
        public static readonly DerObjectIdentifier id_alg_unsigned = pkix_algorithms.Branch("36");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.9</c>.</summary>
        public static readonly DerObjectIdentifier id_pda = IdPkix.Branch("9");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48</c>.</summary>
        //
        // authority information access
        //
        public static readonly DerObjectIdentifier IdAD = IdPkix.Branch("48");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1</c>.</summary>
        public static readonly DerObjectIdentifier IdADOcsp = IdAD.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.2</c>.</summary>
        public static readonly DerObjectIdentifier IdADCAIssuers = IdAD.Branch("2");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1</c>.</summary>
        //
        // OID for ocsp and crl uri in AuthorityInformationAccess extension
        //
        public static readonly DerObjectIdentifier OcspAccessMethod = IdADOcsp;
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.2</c>.</summary>
        public static readonly DerObjectIdentifier CrlAccessMethod = IdADCAIssuers;

        /// <summary>The object identifier <c>2.5.29</c>.</summary>
        public static readonly DerObjectIdentifier id_ce = new DerObjectIdentifier("2.5.29");

        /// <summary>
        /// Google's Certificate Transparency arc, the parent of the OIDs defined by RFC 6962.
        /// </summary>
        /// <remarks>
        /// Not under the standard PKIX id-pe/id-ce trees because the values predate RFC 6962's transition to IETF
        /// process.
        /// </remarks>
        public static readonly DerObjectIdentifier id_ct = new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4");
    }
}
