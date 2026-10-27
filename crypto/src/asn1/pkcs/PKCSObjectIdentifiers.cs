using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>Object identifiers for the PKCS standards.</summary>
    // TODO[api] Make static
    public abstract class PkcsObjectIdentifiers
    {
        /// <summary>The <c>Pkcs1</c> constant, with the value <c>1.2.840.113549.1.1</c>.</summary>
        //
        // pkcs-1 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
        //
        public const string Pkcs1 = "1.2.840.113549.1.1";
        /// <summary>The object identifier <c>1.2.840.113549.1.1</c>.</summary>
        public static readonly DerObjectIdentifier pkcs_1 = new DerObjectIdentifier(Pkcs1);

        /// <summary>The object identifier <c>1.2.840.113549.1.1.1</c>.</summary>
        public static readonly DerObjectIdentifier RsaEncryption = pkcs_1.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.2</c>.</summary>
        public static readonly DerObjectIdentifier MD2WithRsaEncryption = pkcs_1.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.3</c>.</summary>
        public static readonly DerObjectIdentifier MD4WithRsaEncryption = pkcs_1.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.4</c>.</summary>
        public static readonly DerObjectIdentifier MD5WithRsaEncryption = pkcs_1.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.5</c>.</summary>
        public static readonly DerObjectIdentifier Sha1WithRsaEncryption = pkcs_1.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.6</c>.</summary>
        public static readonly DerObjectIdentifier SrsaOaepEncryptionSet = pkcs_1.Branch("6");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.7</c>.</summary>
        public static readonly DerObjectIdentifier IdRsaesOaep = pkcs_1.Branch("7");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.8</c>.</summary>
        public static readonly DerObjectIdentifier IdMgf1 = pkcs_1.Branch("8");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.9</c>.</summary>
        public static readonly DerObjectIdentifier IdPSpecified = pkcs_1.Branch("9");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.10</c>.</summary>
        public static readonly DerObjectIdentifier IdRsassaPss = pkcs_1.Branch("10");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.11</c>.</summary>
        public static readonly DerObjectIdentifier Sha256WithRsaEncryption = pkcs_1.Branch("11");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.12</c>.</summary>
        public static readonly DerObjectIdentifier Sha384WithRsaEncryption = pkcs_1.Branch("12");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.13</c>.</summary>
        public static readonly DerObjectIdentifier Sha512WithRsaEncryption = pkcs_1.Branch("13");
        /// <summary>The object identifier <c>1.2.840.113549.1.1.14</c>.</summary>
        public static readonly DerObjectIdentifier Sha224WithRsaEncryption = pkcs_1.Branch("14");
        /** PKCS#1: 1.2.840.113549.1.1.15 */
        public static readonly DerObjectIdentifier Sha512_224WithRSAEncryption = pkcs_1.Branch("15");
        /** PKCS#1: 1.2.840.113549.1.1.16 */
        public static readonly DerObjectIdentifier Sha512_256WithRSAEncryption = pkcs_1.Branch("16");

        /// <summary>The <c>Pkcs3</c> constant, with the value <c>1.2.840.113549.1.3</c>.</summary>
        //
        // pkcs-3 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
        //
        public const string Pkcs3 = "1.2.840.113549.1.3";
        /// <summary>The object identifier <c>1.2.840.113549.1.3</c>.</summary>
        public static readonly DerObjectIdentifier pkcs_3 = new DerObjectIdentifier(Pkcs3);

        /// <summary>The object identifier <c>1.2.840.113549.1.3.1</c>.</summary>
        public static readonly DerObjectIdentifier DhKeyAgreement = pkcs_3.Branch("1");

        /// <summary>The <c>Pkcs5</c> constant, with the value <c>1.2.840.113549.1.5</c>.</summary>
        //
        // pkcs-5 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
        //
        public const string Pkcs5 = "1.2.840.113549.1.5";
        /// <summary>The object identifier <c>1.2.840.113549.1.5</c>.</summary>
        public static readonly DerObjectIdentifier pkcs_5 = new DerObjectIdentifier(Pkcs5);

        /// <summary>The object identifier <c>1.2.840.113549.1.5.1</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithMD2AndDesCbc = pkcs_5.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.4</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithMD2AndRC2Cbc = pkcs_5.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.3</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithMD5AndDesCbc = pkcs_5.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.6</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithMD5AndRC2Cbc = pkcs_5.Branch("6");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.10</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithSha1AndDesCbc = pkcs_5.Branch("10");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.11</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithSha1AndRC2Cbc = pkcs_5.Branch("11");

        /// <summary>The object identifier <c>1.2.840.113549.1.5.12</c>.</summary>
        public static readonly DerObjectIdentifier IdPbkdf2 = pkcs_5.Branch("12");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.13</c>.</summary>
        public static readonly DerObjectIdentifier IdPbeS2 = pkcs_5.Branch("13");
        /// <summary>The object identifier <c>1.2.840.113549.1.5.14</c>.</summary>
        public static readonly DerObjectIdentifier IdPbmac1 = pkcs_5.Branch("14");

        /// <summary>The <c>EncryptionAlgorithm</c> constant, with the value <c>1.2.840.113549.3</c>.</summary>
        //
        // encryptionAlgorithm OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
        //
        public const string EncryptionAlgorithm = "1.2.840.113549.3";
        private static readonly DerObjectIdentifier EncryptionAlgorithmOid = new DerObjectIdentifier(EncryptionAlgorithm);

        /// <summary>The object identifier <c>1.2.840.113549.3.7</c>.</summary>
        public static readonly DerObjectIdentifier DesEde3Cbc = EncryptionAlgorithmOid.Branch("7");
        /// <summary>The object identifier <c>1.2.840.113549.3.2</c>.</summary>
        public static readonly DerObjectIdentifier RC2Cbc = EncryptionAlgorithmOid.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.3.4</c>.</summary>
        public static readonly DerObjectIdentifier rc4 = EncryptionAlgorithmOid.Branch("4");

        /// <summary>The <c>DigestAlgorithm</c> constant, with the value <c>1.2.840.113549.2</c>.</summary>
        //
        // object identifiers for digests
        //
        public const string DigestAlgorithm = "1.2.840.113549.2";
        private static readonly DerObjectIdentifier DigestAlgorithmOid = new DerObjectIdentifier(DigestAlgorithm);

        /// <summary>The object identifier <c>1.2.840.113549.2.2</c>.</summary>
        //
        // md2 OBJECT IDENTIFIER ::=
        //      {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 2}
        //
        public static readonly DerObjectIdentifier MD2 = DigestAlgorithmOid.Branch("2");

        /// <summary>The object identifier <c>1.2.840.113549.2.4</c>.</summary>
        //
        // md4 OBJECT IDENTIFIER ::=
        //      {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 4}
        //
        public static readonly DerObjectIdentifier MD4 = DigestAlgorithmOid.Branch("4");

        /// <summary>The object identifier <c>1.2.840.113549.2.5</c>.</summary>
        //
        // md5 OBJECT IDENTIFIER ::=
        //      {iso(1) member-body(2) US(840) rsadsi(113549) DigestAlgorithm(2) 5}
        //
        public static readonly DerObjectIdentifier MD5 = DigestAlgorithmOid.Branch("5");

        /// <summary>The object identifier <c>1.2.840.113549.2.7</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha1 = DigestAlgorithmOid.Branch("7");
        /// <summary>The object identifier <c>1.2.840.113549.2.8</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha224 = DigestAlgorithmOid.Branch("8");
        /// <summary>The object identifier <c>1.2.840.113549.2.9</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha256 = DigestAlgorithmOid.Branch("9");
        /// <summary>The object identifier <c>1.2.840.113549.2.10</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha384 = DigestAlgorithmOid.Branch("10");
        /// <summary>The object identifier <c>1.2.840.113549.2.11</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha512 = DigestAlgorithmOid.Branch("11");
        /// <summary>The object identifier <c>1.2.840.113549.2.12</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha512_224 = DigestAlgorithmOid.Branch("12");
        /// <summary>The object identifier <c>1.2.840.113549.2.13</c>.</summary>
        public static readonly DerObjectIdentifier IdHmacWithSha512_256 = DigestAlgorithmOid.Branch("13");

        /// <summary>The <c>Pkcs7</c> constant, with the value <c>1.2.840.113549.1.7</c>.</summary>
        //
        // pkcs-7 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
        //
        public const string Pkcs7 = "1.2.840.113549.1.7";
        /// <summary>The object identifier <c>1.2.840.113549.1.7</c>.</summary>
        public static readonly DerObjectIdentifier pkcs_7 = new DerObjectIdentifier(Pkcs7);

        /// <summary>The object identifier <c>1.2.840.113549.1.7.1</c>.</summary>
        public static readonly DerObjectIdentifier Data = pkcs_7.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.7.2</c>.</summary>
        public static readonly DerObjectIdentifier SignedData = pkcs_7.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.7.3</c>.</summary>
        public static readonly DerObjectIdentifier EnvelopedData = pkcs_7.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.7.4</c>.</summary>
        public static readonly DerObjectIdentifier SignedAndEnvelopedData = pkcs_7.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.7.5</c>.</summary>
        public static readonly DerObjectIdentifier DigestedData = pkcs_7.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.7.6</c>.</summary>
        public static readonly DerObjectIdentifier EncryptedData = pkcs_7.Branch("6");

        /// <summary>The <c>Pkcs9</c> constant, with the value <c>1.2.840.113549.1.9</c>.</summary>
        //
        // pkcs-9 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
        //
        public const string Pkcs9 = "1.2.840.113549.1.9";
        /// <summary>The object identifier <c>1.2.840.113549.1.9</c>.</summary>
        public static readonly DerObjectIdentifier pkcs_9 = new DerObjectIdentifier(Pkcs9);

        /// <summary>The object identifier <c>1.2.840.113549.1.9.1</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtEmailAddress = pkcs_9.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.2</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtUnstructuredName = pkcs_9.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.3</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtContentType = pkcs_9.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.4</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtMessageDigest = pkcs_9.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.5</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtSigningTime = pkcs_9.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.6</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtCounterSignature = pkcs_9.Branch("6");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.7</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtChallengePassword = pkcs_9.Branch("7");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.8</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtUnstructuredAddress = pkcs_9.Branch("8");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.9</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtExtendedCertificateAttributes = pkcs_9.Branch("9");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.13</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtSigningDescription = pkcs_9.Branch("13");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.14</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtExtensionRequest = pkcs_9.Branch("14");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtSmimeCapabilities = pkcs_9.Branch("15");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16</c>.</summary>
        public static readonly DerObjectIdentifier IdSmime = pkcs_9.Branch("16");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.20</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtFriendlyName = pkcs_9.Branch("20");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.21</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtLocalKeyID = pkcs_9.Branch("21");

        /// <summary>The dotted-decimal string of the certificate types branch, <c>1.2.840.113549.1.9.22</c>.</summary>
        public const string CertTypes = Pkcs9 + ".22";
        private static readonly DerObjectIdentifier cert_types = pkcs_9.Branch("22");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.22.1</c>.</summary>
        public static readonly DerObjectIdentifier X509Certificate = cert_types.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.22.2</c>.</summary>
        public static readonly DerObjectIdentifier SdsiCertificate = cert_types.Branch("2");

        /// <summary>The dotted-decimal string of the CRL types branch, <c>1.2.840.113549.1.9.23</c>.</summary>
        public const string CrlTypes = Pkcs9 + ".23";
        private static readonly DerObjectIdentifier crl_types = pkcs_9.Branch("23");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.23.1</c>.</summary>
        public static readonly DerObjectIdentifier X509Crl = crl_types.Branch("1");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3</c>.</summary>
        public static readonly DerObjectIdentifier smime_alg = IdSmime.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3</c>.</summary>
        [Obsolete("Use 'smime_alg' instead")]
        public static readonly DerObjectIdentifier id_alg = smime_alg;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3</c>.</summary>
        [Obsolete("Use 'smime_alg' instead")]
        public static readonly DerObjectIdentifier IdAlg = id_alg;

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.5</c>.</summary>
        public static readonly DerObjectIdentifier IdAlgEsdh = smime_alg.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.6</c>.</summary>
        public static readonly DerObjectIdentifier IdAlgCms3DesWrap = smime_alg.Branch("6");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.7</c>.</summary>
        public static readonly DerObjectIdentifier IdAlgCmsRC2Wrap = smime_alg.Branch("7");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.8</c>.</summary>
        public static readonly DerObjectIdentifier IdAlgZlibCompress = smime_alg.Branch("8");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.9</c>.</summary>
        public static readonly DerObjectIdentifier IdAlgPwriKek = smime_alg.Branch("9");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.10</c>.</summary>
        public static readonly DerObjectIdentifier IdAlgSsdh = smime_alg.Branch("10");

        /** RFC 6211 -  id-aa-cmsAlgorithmProtect OBJECT IDENTIFIER ::= {
         * iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 52 } */
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
        public static readonly DerObjectIdentifier IdRsaKem = smime_alg.Branch("14");

        /**
         * id-alg-hss-lms-hashsig OBJECT IDENTIFIER ::= { iso(1)
         *     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
         *    smime(16) alg(3) 17 }
         */
        public static readonly DerObjectIdentifier IdAlgHssLmsHashsig = smime_alg.Branch("17");

        /**
         * <pre>
         * id-alg-AEADChaCha20Poly1305 OBJECT IDENTIFIER ::=
         * { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
         *    pkcs9(9) smime(16) alg(3) 18 }
         *
         * AEADChaCha20Poly1305Nonce ::= OCTET STRING (SIZE(12))
         * </pre>
         */
        public static readonly DerObjectIdentifier IdAlgAeadChaCha20Poly1305 = smime_alg.Branch("18");

        /**
         * RFC 8418: dhSinglePass-stdDH-hkdf-sha256-scheme OBJECT IDENTIFIER ::= { smime-alg 19 }
         * <p>
         * 1.2.840.113549.1.9.16.3.19
         * </p>
         */
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_hkdf_sha256_scheme = smime_alg.Branch("19");

        /**
         * RFC 8418: dhSinglePass-stdDH-hkdf-sha384-scheme OBJECT IDENTIFIER ::= { smime-alg 20 }
         * <p>
         * 1.2.840.113549.1.9.16.3.20
         * </p>
         */
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_hkdf_sha384_scheme = smime_alg.Branch("20");

        /**
         * RFC 8418: dhSinglePass-stdDH-hkdf-sha512-scheme OBJECT IDENTIFIER ::= { smime-alg 21 }
         * <p>
         * 1.2.840.113549.1.9.16.3.21
         * </p>
         */
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_hkdf_sha512_scheme = smime_alg.Branch("21");

        /**
         * <pre>
         *    id-alg-hkdf-with-sha256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 28 }
         * </pre>
         */
        public static readonly DerObjectIdentifier IdAlgHkdfWithSha256 = smime_alg.Branch("28");

        /**
         * <pre>
         *    id-alg-hkdf-with-sha384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 29 }
         * </pre>
         */
        public static readonly DerObjectIdentifier IdAlgHkdfWithSha384 = smime_alg.Branch("29");

        /**
         * <pre>
         *    id-alg-hkdf-with-sha512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 30 }
         * </pre>
         */
        public static readonly DerObjectIdentifier IdAlgHkdfWithSha512 = smime_alg.Branch("30");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.1</c>.</summary>
        //
        // SMIME capability sub oids.
        //
        public static readonly DerObjectIdentifier PreferSignedData = Pkcs9AtSmimeCapabilities.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.2</c>.</summary>
        public static readonly DerObjectIdentifier CannotDecryptAny = Pkcs9AtSmimeCapabilities.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.3</c>.</summary>
        public static readonly DerObjectIdentifier SmimeCapabilitiesVersions = Pkcs9AtSmimeCapabilities.Branch("3");

        /// <summary>The <c>IdCT</c> constant, with the value <c>1.2.840.113549.1.9.16.1</c>.</summary>
        //
        // id-ct OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
        //
        public const string IdCT = "1.2.840.113549.1.9.16.1";
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1</c>.</summary>
        public static readonly DerObjectIdentifier id_ct = IdSmime.Branch("1");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.2</c>.</summary>
        public static readonly DerObjectIdentifier IdCTAuthData = id_ct.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.4</c>.</summary>
        public static readonly DerObjectIdentifier IdCTTstInfo = id_ct.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.9</c>.</summary>
        public static readonly DerObjectIdentifier IdCTCompressedData = id_ct.Branch("9");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.23</c>.</summary>
        public static readonly DerObjectIdentifier IdCTAuthEnvelopedData = id_ct.Branch("23");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.31</c>.</summary>
        public static readonly DerObjectIdentifier IdCTTimestampedData = id_ct.Branch("31");

        /// <summary>The <c>IdCti</c> constant, with the value <c>1.2.840.113549.1.9.16.6</c>.</summary>
        //
        // id-cti OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
        //
        public const string IdCti = "1.2.840.113549.1.9.16.6";
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6</c>.</summary>
        public static readonly DerObjectIdentifier id_cti = IdSmime.Branch("6");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.1</c>.</summary>
        public static readonly DerObjectIdentifier IdCtiEtsProofOfOrigin = id_cti.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.2</c>.</summary>
        public static readonly DerObjectIdentifier IdCtiEtsProofOfReceipt = id_cti.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.3</c>.</summary>
        public static readonly DerObjectIdentifier IdCtiEtsProofOfDelivery = id_cti.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.4</c>.</summary>
        public static readonly DerObjectIdentifier IdCtiEtsProofOfSender = id_cti.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.5</c>.</summary>
        public static readonly DerObjectIdentifier IdCtiEtsProofOfApproval = id_cti.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.6</c>.</summary>
        public static readonly DerObjectIdentifier IdCtiEtsProofOfCreation = id_cti.Branch("6");

        /// <summary>The <c>IdAA</c> constant, with the value <c>1.2.840.113549.1.9.16.2</c>.</summary>
        //
        // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
        //
        public const string IdAA = "1.2.840.113549.1.9.16.2";

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2</c>.</summary>
        public static readonly DerObjectIdentifier id_aa = IdSmime.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2</c>.</summary>
        [Obsolete("Use 'id_aa' instead")]
        public static readonly DerObjectIdentifier IdAAOid = id_aa;

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.46</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs9AtBinarySigningTime = id_aa.Branch("46");

        /** PKCS#9: 1.2.840.113549.1.9.16.2.1 -- smime attribute receiptRequest */
        public static readonly DerObjectIdentifier IdAAReceiptRequest = id_aa.Branch("1");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.4</c>.</summary>
        public static readonly DerObjectIdentifier IdAAContentHint = id_aa.Branch("4"); // See RFC 2634
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.5</c>.</summary>
        public static readonly DerObjectIdentifier IdAAMsgSigDigest = id_aa.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.10</c>.</summary>
        public static readonly DerObjectIdentifier IdAAContentReference = id_aa.Branch("10");

        /*
         * id-aa-encrypKeyPref OBJECT IDENTIFIER ::= {id-aa 11}
         */
        public static readonly DerObjectIdentifier IdAAEncrypKeyPref = id_aa.Branch("11");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.12</c>.</summary>
        public static readonly DerObjectIdentifier IdAASigningCertificate = id_aa.Branch("12");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.47</c>.</summary>
        public static readonly DerObjectIdentifier IdAASigningCertificateV2 = id_aa.Branch("47");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.7</c>.</summary>
        public static readonly DerObjectIdentifier IdAAContentIdentifier = id_aa.Branch("7"); // See RFC 2634

        /*
         * RFC 3126
         */
        public static readonly DerObjectIdentifier IdAASignatureTimeStampToken = id_aa.Branch("14");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.15</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsSigPolicyID = id_aa.Branch("15");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.16</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsCommitmentType = id_aa.Branch("16");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.17</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsSignerLocation = id_aa.Branch("17");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.18</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsSignerAttr = id_aa.Branch("18");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.19</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsOtherSigCert = id_aa.Branch("19");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.20</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsContentTimestamp = id_aa.Branch("20");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.21</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsCertificateRefs = id_aa.Branch("21");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.22</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsRevocationRefs = id_aa.Branch("22");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.23</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsCertValues = id_aa.Branch("23");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.24</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsRevocationValues = id_aa.Branch("24");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.25</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsEscTimeStamp = id_aa.Branch("25");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.26</c>.</summary>
        public static readonly DerObjectIdentifier IdAAEtsCertCrlTimestamp = id_aa.Branch("26");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.27</c>.</summary>
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

        /**
         * PKCS#9: 1.2.840.113549.1.9.16.2.60 - RFC 9763 sec. 4:
         * {@code id-aa-relatedCertRequest} attribute identifying a previously issued certificate
         * that should be bound to the CSR being processed (hybrid PQ migration). The attribute
         * value is a {@code RequesterCertificate} SEQUENCE carrying the
         * IssuerAndSerialNumber of the related certificate, a BinaryTime freshness
         * stamp, one or more URIs from which the related certificate can be fetched,
         * and a signature over the concatenation of the DER-encoded certID and
         * requestTime computed with the related certificate's private key.
         */
        public static readonly DerObjectIdentifier IdAARelatedCertRequest = id_aa.Branch("60");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.48</c>.</summary>
        // RFC 5126
        public static readonly DerObjectIdentifier IdAAEtsArchiveTimestampV2 = id_aa.Branch("48");

        /// <summary>The <c>IdSpq</c> constant, with the value <c>1.2.840.113549.1.9.16.5</c>.</summary>
        //
        // id-spq OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
        // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-spq(5)}
        //
        public const string IdSpq = "1.2.840.113549.1.9.16.5";
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.5</c>.</summary>
        public static readonly DerObjectIdentifier id_spq = IdSmime.Branch("5");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.5.1</c>.</summary>
        public static readonly DerObjectIdentifier IdSpqEtsUri = id_spq.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.5.2</c>.</summary>
        public static readonly DerObjectIdentifier IdSpqEtsUNotice = id_spq.Branch("2");

        /// <summary>The <c>Pkcs12</c> constant, with the value <c>1.2.840.113549.1.12</c>.</summary>
        //
        // pkcs-12 OBJECT IDENTIFIER ::= {
        //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
        //
        public const string Pkcs12 = "1.2.840.113549.1.12";
        /// <summary>
        /// The dotted-decimal string of the PKCS#12 bag types branch, <c>1.2.840.113549.1.12.10.1</c>.
        /// </summary>
        public const string BagTypes = Pkcs12 + ".10.1";

        private static readonly DerObjectIdentifier pkcs_12_bag_types = new DerObjectIdentifier(BagTypes);

        /// <summary>The object identifier <c>1.2.840.113549.1.12.10.1.1</c>.</summary>
        public static readonly DerObjectIdentifier KeyBag = pkcs_12_bag_types.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.10.1.2</c>.</summary>
        public static readonly DerObjectIdentifier Pkcs8ShroudedKeyBag = pkcs_12_bag_types.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.10.1.3</c>.</summary>
        public static readonly DerObjectIdentifier CertBag = pkcs_12_bag_types.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.10.1.4</c>.</summary>
        public static readonly DerObjectIdentifier CrlBag = pkcs_12_bag_types.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.10.1.5</c>.</summary>
        public static readonly DerObjectIdentifier SecretBag = pkcs_12_bag_types.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.10.1.6</c>.</summary>
        public static readonly DerObjectIdentifier SafeContentsBag = pkcs_12_bag_types.Branch("6");

        /// <summary>
        /// The dotted-decimal string of the PKCS#12 password-based encryption branch, <c>1.2.840.113549.1.12.1</c>.
        /// </summary>
        public const string Pkcs12PbeIds = Pkcs12 + ".1";

        private static readonly DerObjectIdentifier pkcs_12_pbe_ids = new DerObjectIdentifier(Pkcs12PbeIds);

        /// <summary>The object identifier <c>1.2.840.113549.1.12.1.1</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC4 = pkcs_12_pbe_ids.Branch("1");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.1.2</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd40BitRC4 = pkcs_12_pbe_ids.Branch("2");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.1.3</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd3KeyTripleDesCbc = pkcs_12_pbe_ids.Branch("3");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.1.4</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd2KeyTripleDesCbc = pkcs_12_pbe_ids.Branch("4");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.1.5</c>.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC2Cbc = pkcs_12_pbe_ids.Branch("5");
        /// <summary>The object identifier <c>1.2.840.113549.1.12.1.6</c>.</summary>
        public static readonly DerObjectIdentifier PbewithShaAnd40BitRC2Cbc = pkcs_12_pbe_ids.Branch("6");
    }
}
