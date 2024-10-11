using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    // TODO[api] Make static
    public abstract class PkcsObjectIdentifiers
    {
        //
        // pkcs-1 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
        //
        public const string Pkcs1 = "1.2.840.113549.1.1";
        public static readonly DerObjectIdentifier pkcs_1 = new DerObjectIdentifier(Pkcs1);

        public static readonly DerObjectIdentifier RsaEncryption            = pkcs_1.Branch("1");
        public static readonly DerObjectIdentifier MD2WithRsaEncryption		= pkcs_1.Branch("2");
        public static readonly DerObjectIdentifier MD4WithRsaEncryption		= pkcs_1.Branch("3");
        public static readonly DerObjectIdentifier MD5WithRsaEncryption		= pkcs_1.Branch("4");
        public static readonly DerObjectIdentifier Sha1WithRsaEncryption	= pkcs_1.Branch("5");
        public static readonly DerObjectIdentifier SrsaOaepEncryptionSet	= pkcs_1.Branch("6");
        public static readonly DerObjectIdentifier IdRsaesOaep				= pkcs_1.Branch("7");
        public static readonly DerObjectIdentifier IdMgf1					= pkcs_1.Branch("8");
        public static readonly DerObjectIdentifier IdPSpecified				= pkcs_1.Branch("9");
        public static readonly DerObjectIdentifier IdRsassaPss				= pkcs_1.Branch("10");
        public static readonly DerObjectIdentifier Sha256WithRsaEncryption	= pkcs_1.Branch("11");
        public static readonly DerObjectIdentifier Sha384WithRsaEncryption	= pkcs_1.Branch("12");
        public static readonly DerObjectIdentifier Sha512WithRsaEncryption	= pkcs_1.Branch("13");
        public static readonly DerObjectIdentifier Sha224WithRsaEncryption	= pkcs_1.Branch("14");
        /** PKCS#1: 1.2.840.113549.1.1.15 */
        public static readonly DerObjectIdentifier Sha512_224WithRSAEncryption = pkcs_1.Branch("15");
        /** PKCS#1: 1.2.840.113549.1.1.16 */
        public static readonly DerObjectIdentifier Sha512_256WithRSAEncryption = pkcs_1.Branch("16");

        //
        // pkcs-3 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
        //
        public const string Pkcs3 = "1.2.840.113549.1.3";
        public static readonly DerObjectIdentifier pkcs_3 = new DerObjectIdentifier(Pkcs3);

        public static readonly DerObjectIdentifier DhKeyAgreement = pkcs_3.Branch("1");

		//
        // pkcs-5 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
        //
        public const string Pkcs5 = "1.2.840.113549.1.5";
        public static readonly DerObjectIdentifier pkcs_5 = new DerObjectIdentifier(Pkcs5);

        public static readonly DerObjectIdentifier PbeWithMD2AndDesCbc    = pkcs_5.Branch("1");
        public static readonly DerObjectIdentifier PbeWithMD2AndRC2Cbc    = pkcs_5.Branch("4");
        public static readonly DerObjectIdentifier PbeWithMD5AndDesCbc    = pkcs_5.Branch("3");
        public static readonly DerObjectIdentifier PbeWithMD5AndRC2Cbc    = pkcs_5.Branch("6");
        public static readonly DerObjectIdentifier PbeWithSha1AndDesCbc   = pkcs_5.Branch("10");
        public static readonly DerObjectIdentifier PbeWithSha1AndRC2Cbc   = pkcs_5.Branch("11");

        public static readonly DerObjectIdentifier IdPbkdf2 = pkcs_5.Branch("12");
        public static readonly DerObjectIdentifier IdPbeS2 = pkcs_5.Branch("13");
        public static readonly DerObjectIdentifier IdPbmac1 = pkcs_5.Branch("14");

        //
        // encryptionAlgorithm OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
        //
        public const string EncryptionAlgorithm = "1.2.840.113549.3";
        private static readonly DerObjectIdentifier EncryptionAlgorithmOid = new DerObjectIdentifier(EncryptionAlgorithm);

		public static readonly DerObjectIdentifier DesEde3Cbc	= EncryptionAlgorithmOid.Branch("7");
        public static readonly DerObjectIdentifier RC2Cbc		= EncryptionAlgorithmOid.Branch("2");
        public static readonly DerObjectIdentifier rc4          = EncryptionAlgorithmOid.Branch("4");

        //
        // object identifiers for digests
        //
        public const string DigestAlgorithm = "1.2.840.113549.2";
        private static readonly DerObjectIdentifier DigestAlgorithmOid = new DerObjectIdentifier(DigestAlgorithm);

        //
        // md2 OBJECT IDENTIFIER ::=
        //      {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 2}
        //
        public static readonly DerObjectIdentifier MD2 = DigestAlgorithmOid.Branch("2");

        //
        // md4 OBJECT IDENTIFIER ::=
        //      {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 4}
        //
        public static readonly DerObjectIdentifier MD4 = DigestAlgorithmOid.Branch("4");

        //
        // md5 OBJECT IDENTIFIER ::=
        //      {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 5}
        //
        public static readonly DerObjectIdentifier MD5 = DigestAlgorithmOid.Branch("5");

		public static readonly DerObjectIdentifier IdHmacWithSha1	= DigestAlgorithmOid.Branch("7");
        public static readonly DerObjectIdentifier IdHmacWithSha224	= DigestAlgorithmOid.Branch("8");
        public static readonly DerObjectIdentifier IdHmacWithSha256	= DigestAlgorithmOid.Branch("9");
        public static readonly DerObjectIdentifier IdHmacWithSha384	= DigestAlgorithmOid.Branch("10");
        public static readonly DerObjectIdentifier IdHmacWithSha512	= DigestAlgorithmOid.Branch("11");
        public static readonly DerObjectIdentifier IdHmacWithSha512_224 = DigestAlgorithmOid.Branch("12");
        public static readonly DerObjectIdentifier IdHmacWithSha512_256 = DigestAlgorithmOid.Branch("13");

        //
        // pkcs-7 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
        //
        public const string Pkcs7 = "1.2.840.113549.1.7";
        public static readonly DerObjectIdentifier pkcs_7 = new DerObjectIdentifier(Pkcs7);

		public static readonly DerObjectIdentifier Data                    = pkcs_7.Branch("1");
        public static readonly DerObjectIdentifier SignedData              = pkcs_7.Branch("2");
        public static readonly DerObjectIdentifier EnvelopedData           = pkcs_7.Branch("3");
        public static readonly DerObjectIdentifier SignedAndEnvelopedData  = pkcs_7.Branch("4");
        public static readonly DerObjectIdentifier DigestedData            = pkcs_7.Branch("5");
        public static readonly DerObjectIdentifier EncryptedData           = pkcs_7.Branch("6");

        //
        // pkcs-9 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
        //
        public const string Pkcs9 = "1.2.840.113549.1.9";
        public static readonly DerObjectIdentifier pkcs_9 = new DerObjectIdentifier(Pkcs9);

        public static readonly DerObjectIdentifier Pkcs9AtEmailAddress					= pkcs_9.Branch("1");
        public static readonly DerObjectIdentifier Pkcs9AtUnstructuredName				= pkcs_9.Branch("2");
        public static readonly DerObjectIdentifier Pkcs9AtContentType					= pkcs_9.Branch("3");
        public static readonly DerObjectIdentifier Pkcs9AtMessageDigest					= pkcs_9.Branch("4");
        public static readonly DerObjectIdentifier Pkcs9AtSigningTime					= pkcs_9.Branch("5");
        public static readonly DerObjectIdentifier Pkcs9AtCounterSignature				= pkcs_9.Branch("6");
        public static readonly DerObjectIdentifier Pkcs9AtChallengePassword				= pkcs_9.Branch("7");
        public static readonly DerObjectIdentifier Pkcs9AtUnstructuredAddress			= pkcs_9.Branch("8");
        public static readonly DerObjectIdentifier Pkcs9AtExtendedCertificateAttributes	= pkcs_9.Branch("9");
        public static readonly DerObjectIdentifier Pkcs9AtSigningDescription			= pkcs_9.Branch("13");
        public static readonly DerObjectIdentifier Pkcs9AtExtensionRequest				= pkcs_9.Branch("14");
        public static readonly DerObjectIdentifier Pkcs9AtSmimeCapabilities				= pkcs_9.Branch("15");
        public static readonly DerObjectIdentifier IdSmime                              = pkcs_9.Branch("16");
        public static readonly DerObjectIdentifier Pkcs9AtBinarySigningTime             = pkcs_9.Branch("16.2.46");

        public static readonly DerObjectIdentifier Pkcs9AtFriendlyName					= pkcs_9.Branch("20");
        public static readonly DerObjectIdentifier Pkcs9AtLocalKeyID					= pkcs_9.Branch("21");

		public const string CertTypes = Pkcs9 + ".22";
        private static readonly DerObjectIdentifier cert_types = pkcs_9.Branch("22");

		public static readonly DerObjectIdentifier X509Certificate = cert_types.Branch("1");
		public static readonly DerObjectIdentifier SdsiCertificate = cert_types.Branch("2");

		public const string CrlTypes = Pkcs9 + ".23";
        private static readonly DerObjectIdentifier crl_types = pkcs_9.Branch("23");

        public static readonly DerObjectIdentifier X509Crl = crl_types.Branch("1");

        public static readonly DerObjectIdentifier IdAlg = IdSmime.Branch("3");

        public static readonly DerObjectIdentifier IdAlgEsdh            = IdAlg.Branch("5");
        public static readonly DerObjectIdentifier IdAlgCms3DesWrap     = IdAlg.Branch("6");
        public static readonly DerObjectIdentifier IdAlgCmsRC2Wrap      = IdAlg.Branch("7");
        public static readonly DerObjectIdentifier IdAlgZlibCompress    = IdAlg.Branch("8");
        public static readonly DerObjectIdentifier IdAlgPwriKek         = IdAlg.Branch("9");
        public static readonly DerObjectIdentifier IdAlgSsdh            = IdAlg.Branch("10");

        /** RFC 6211 -  id-aa-cmsAlgorithmProtect OBJECT IDENTIFIER ::= {
iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
pkcs9(9) 52 }  */
        public static readonly DerObjectIdentifier id_aa_cmsAlgorithmProtect = pkcs_9.Branch("52");

        /*
         * <pre>
         * -- RSA-KEM Key Transport Algorithm
         *
         * id-rsa-kem OID ::= {
         *      iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
         *      pkcs-9(9) smime(16) alg(3) 14
         *   }
         * </pre>
         */
        public static readonly DerObjectIdentifier IdRsaKem = IdAlg.Branch("14");

        /**
         * id-alg-hss-lms-hashsig OBJECT IDENTIFIER ::= { iso(1)
         *     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
         *    smime(16) alg(3) 17 }
         */
        public static readonly DerObjectIdentifier IdAlgHssLmsHashsig = IdAlg.Branch("17");

        /**
         * <pre>
         * id-alg-AEADChaCha20Poly1305 OBJECT IDENTIFIER ::=
         * { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
         *    pkcs9(9) smime(16) alg(3) 18 }
         *
         * AEADChaCha20Poly1305Nonce ::= OCTET STRING (SIZE(12))
         * </pre>
         */
        public static readonly DerObjectIdentifier IdAlgAeadChaCha20Poly1305 = IdAlg.Branch("18");

        /**
         * <pre>
         *    id-alg-hkdf-with-sha256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 28 }
         * </pre>
         */
        public static readonly DerObjectIdentifier id_alg_hkdf_with_sha256 = IdAlg.Branch("28");

        /**
         * <pre>
         *    id-alg-hkdf-with-sha384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 29 }
         * </pre>
         */
        public static readonly DerObjectIdentifier id_alg_hkdf_with_sha384 = IdAlg.Branch("29");

        /**
         * <pre>
         *    id-alg-hkdf-with-sha512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 30 }
         * </pre>
         */
        public static readonly DerObjectIdentifier id_alg_hkdf_with_sha512 = IdAlg.Branch("30");

        //
        // SMIME capability sub oids.
        //
        public static readonly DerObjectIdentifier PreferSignedData				= Pkcs9AtSmimeCapabilities.Branch("1");
        public static readonly DerObjectIdentifier CannotDecryptAny             = Pkcs9AtSmimeCapabilities.Branch("2");
        public static readonly DerObjectIdentifier SmimeCapabilitiesVersions    = Pkcs9AtSmimeCapabilities.Branch("3");

        //
        // other SMIME attributes
        //
        public static readonly DerObjectIdentifier IdAAReceiptRequest = IdSmime.Branch("2.1");

        //
        // id-ct OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
        //
        public const string IdCT = "1.2.840.113549.1.9.16.1";
        public static readonly DerObjectIdentifier id_ct = new DerObjectIdentifier(IdCT);

        public static readonly DerObjectIdentifier IdCTAuthData          = id_ct.Branch("2");
        public static readonly DerObjectIdentifier IdCTTstInfo           = id_ct.Branch("4");
        public static readonly DerObjectIdentifier IdCTCompressedData    = id_ct.Branch("9");
		public static readonly DerObjectIdentifier IdCTAuthEnvelopedData = id_ct.Branch("23");
		public static readonly DerObjectIdentifier IdCTTimestampedData   = id_ct.Branch("31");

        //
        // id-cti OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
        //
        public const string IdCti = "1.2.840.113549.1.9.16.6";
        public static readonly DerObjectIdentifier id_cti = new DerObjectIdentifier(IdCti);

        public static readonly DerObjectIdentifier IdCtiEtsProofOfOrigin	= id_cti.Branch("1");
        public static readonly DerObjectIdentifier IdCtiEtsProofOfReceipt	= id_cti.Branch("2");
        public static readonly DerObjectIdentifier IdCtiEtsProofOfDelivery	= id_cti.Branch("3");
        public static readonly DerObjectIdentifier IdCtiEtsProofOfSender	= id_cti.Branch("4");
        public static readonly DerObjectIdentifier IdCtiEtsProofOfApproval	= id_cti.Branch("5");
        public static readonly DerObjectIdentifier IdCtiEtsProofOfCreation	= id_cti.Branch("6");

        //
        // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
        //
        public const string IdAA = "1.2.840.113549.1.9.16.2";

        public static readonly DerObjectIdentifier id_aa = new DerObjectIdentifier(IdAA);
        [Obsolete("Use 'id_aa' instead")]
        public static readonly DerObjectIdentifier IdAAOid = id_aa;

        /** PKCS#9: 1.2.840.113549.1.9.16.2.1 -- smime attribute receiptRequest */
        public static readonly DerObjectIdentifier id_aa_receiptRequest = id_aa.Branch("1");

        public static readonly DerObjectIdentifier IdAAContentHint = id_aa.Branch("4"); // See RFC 2634
    	public static readonly DerObjectIdentifier IdAAMsgSigDigest = id_aa.Branch("5");
    	public static readonly DerObjectIdentifier IdAAContentReference = id_aa.Branch("10");

		/*
        * id-aa-encrypKeyPref OBJECT IDENTIFIER ::= {id-aa 11}
        *
        */
        public static readonly DerObjectIdentifier IdAAEncrypKeyPref = id_aa.Branch("11");
        public static readonly DerObjectIdentifier IdAASigningCertificate = id_aa.Branch("12");
		public static readonly DerObjectIdentifier IdAASigningCertificateV2 = id_aa.Branch("47");

		public static readonly DerObjectIdentifier IdAAContentIdentifier = id_aa.Branch("7"); // See RFC 2634

		/*
		 * RFC 3126
		 */
		public static readonly DerObjectIdentifier IdAASignatureTimeStampToken = id_aa.Branch("14");

		public static readonly DerObjectIdentifier IdAAEtsSigPolicyID = id_aa.Branch("15");
		public static readonly DerObjectIdentifier IdAAEtsCommitmentType = id_aa.Branch("16");
		public static readonly DerObjectIdentifier IdAAEtsSignerLocation = id_aa.Branch("17");
		public static readonly DerObjectIdentifier IdAAEtsSignerAttr = id_aa.Branch("18");
		public static readonly DerObjectIdentifier IdAAEtsOtherSigCert = id_aa.Branch("19");
		public static readonly DerObjectIdentifier IdAAEtsContentTimestamp = id_aa.Branch("20");
		public static readonly DerObjectIdentifier IdAAEtsCertificateRefs = id_aa.Branch("21");
		public static readonly DerObjectIdentifier IdAAEtsRevocationRefs = id_aa.Branch("22");
		public static readonly DerObjectIdentifier IdAAEtsCertValues = id_aa.Branch("23");
		public static readonly DerObjectIdentifier IdAAEtsRevocationValues = id_aa.Branch("24");
		public static readonly DerObjectIdentifier IdAAEtsEscTimeStamp = id_aa.Branch("25");
		public static readonly DerObjectIdentifier IdAAEtsCertCrlTimestamp = id_aa.Branch("26");
		public static readonly DerObjectIdentifier IdAAEtsArchiveTimestamp = id_aa.Branch("27");

        /** PKCS#9: 1.2.840.113549.1.9.16.2.37 - <a href="https://tools.ietf.org/html/rfc4108#section-2.2.5">RFC 4108</a> */
        public static readonly DerObjectIdentifier IdAADecryptKeyID = id_aa.Branch("37");

        /** PKCS#9: 1.2.840.113549.1.9.16.2.38 - <a href="https://tools.ietf.org/html/rfc4108#section-2.2.6">RFC 4108</a> */
        public static readonly DerObjectIdentifier IdAAImplCryptoAlgs = id_aa.Branch("38");

        /** PKCS#9: 1.2.840.113549.1.9.16.2.54 <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
        public static readonly DerObjectIdentifier IdAAAsymmDecryptKeyID = id_aa.Branch("54");

        /** PKCS#9: 1.2.840.113549.1.9.16.2.43   <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
        public static readonly DerObjectIdentifier IdAAImplCompressAlgs = id_aa.Branch("43");
        /** PKCS#9: 1.2.840.113549.1.9.16.2.40   <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
        public static readonly DerObjectIdentifier IdAACommunityIdentifiers = id_aa.Branch("40");

		//
		// id-spq OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
		// rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-spq(5)}
		//
		public const string IdSpq = "1.2.840.113549.1.9.16.5";
        public static readonly DerObjectIdentifier id_spq = new DerObjectIdentifier(IdSpq);

		public static readonly DerObjectIdentifier IdSpqEtsUri = id_spq.Branch("1");
		public static readonly DerObjectIdentifier IdSpqEtsUNotice = id_spq.Branch("2");

		//
        // pkcs-12 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
        //
        public const string Pkcs12 = "1.2.840.113549.1.12";
        public const string BagTypes = Pkcs12 + ".10.1";

        private static readonly DerObjectIdentifier pkcs_12_bag_types = new DerObjectIdentifier(BagTypes);

        public static readonly DerObjectIdentifier KeyBag				= pkcs_12_bag_types.Branch("1");
        public static readonly DerObjectIdentifier Pkcs8ShroudedKeyBag	= pkcs_12_bag_types.Branch("2");
        public static readonly DerObjectIdentifier CertBag				= pkcs_12_bag_types.Branch("3");
        public static readonly DerObjectIdentifier CrlBag				= pkcs_12_bag_types.Branch("4");
        public static readonly DerObjectIdentifier SecretBag			= pkcs_12_bag_types.Branch("5");
        public static readonly DerObjectIdentifier SafeContentsBag		= pkcs_12_bag_types.Branch("6");

        public const string Pkcs12PbeIds = Pkcs12 + ".1";

        private static readonly DerObjectIdentifier pkcs_12_pbe_ids = new DerObjectIdentifier(Pkcs12PbeIds);

        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC4			= pkcs_12_pbe_ids.Branch("1");
        public static readonly DerObjectIdentifier PbeWithShaAnd40BitRC4			= pkcs_12_pbe_ids.Branch("2");
        public static readonly DerObjectIdentifier PbeWithShaAnd3KeyTripleDesCbc	= pkcs_12_pbe_ids.Branch("3");
        public static readonly DerObjectIdentifier PbeWithShaAnd2KeyTripleDesCbc	= pkcs_12_pbe_ids.Branch("4");
        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC2Cbc		= pkcs_12_pbe_ids.Branch("5");
        public static readonly DerObjectIdentifier PbewithShaAnd40BitRC2Cbc			= pkcs_12_pbe_ids.Branch("6");
    }
}
