using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Isara;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    // TODO[api] Create API for this
    public class DefaultSignatureAlgorithmIdentifierFinder
    {
        public static readonly DefaultSignatureAlgorithmIdentifierFinder Instance =
            new DefaultSignatureAlgorithmIdentifierFinder();

        private static readonly Dictionary<string, DerObjectIdentifier> m_algorithms =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<DerObjectIdentifier> m_noParams = new HashSet<DerObjectIdentifier>();
        private static readonly Dictionary<string, Asn1Encodable> m_parameters =
            new Dictionary<string, Asn1Encodable>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<DerObjectIdentifier> m_pkcs15RsaEncryption = new HashSet<DerObjectIdentifier>();
        private static readonly Dictionary<DerObjectIdentifier, DerObjectIdentifier> m_digestOids =
            new Dictionary<DerObjectIdentifier, DerObjectIdentifier>();

        static DefaultSignatureAlgorithmIdentifierFinder()
        {
            m_algorithms["COMPOSITE"] = MiscObjectIdentifiers.id_alg_composite;

            m_algorithms["MD2WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            m_algorithms["MD2WITHRSA"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            m_algorithms["MD5WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;
            m_algorithms["MD5WITHRSA"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;
            m_algorithms["SHA1WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            m_algorithms["SHA-1WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            m_algorithms["SHA1WITHRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            m_algorithms["SHA-1WITHRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            m_algorithms["SHA224WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            m_algorithms["SHA-224WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            m_algorithms["SHA224WITHRSA"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            m_algorithms["SHA-224WITHRSA"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            m_algorithms["SHA256WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            m_algorithms["SHA-256WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            m_algorithms["SHA256WITHRSA"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            m_algorithms["SHA-256WITHRSA"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            m_algorithms["SHA384WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            m_algorithms["SHA-384WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            m_algorithms["SHA384WITHRSA"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            m_algorithms["SHA-384WITHRSA"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            m_algorithms["SHA512WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            m_algorithms["SHA-512WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            m_algorithms["SHA512WITHRSA"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            m_algorithms["SHA-512WITHRSA"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            m_algorithms["SHA512(224)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            m_algorithms["SHA-512(224)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            m_algorithms["SHA512(224)WITHRSA"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            m_algorithms["SHA-512(224)WITHRSA"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            m_algorithms["SHA512(256)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            m_algorithms["SHA-512(256)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            m_algorithms["SHA512(256)WITHRSA"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            m_algorithms["SHA-512(256)WITHRSA"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            m_algorithms["SHA1WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA224WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA256WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA384WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA512WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA3-224WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA3-256WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA3-384WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["SHA3-512WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            m_algorithms["RIPEMD160WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
            m_algorithms["RIPEMD160WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
            m_algorithms["RIPEMD128WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            m_algorithms["RIPEMD128WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            m_algorithms["RIPEMD256WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
            m_algorithms["RIPEMD256WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
            m_algorithms["SHA1WITHDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;
            m_algorithms["SHA-1WITHDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;
            m_algorithms["DSAWITHSHA1"] = X9ObjectIdentifiers.IdDsaWithSha1;
            m_algorithms["SHA224WITHDSA"] = NistObjectIdentifiers.DsaWithSha224;
            m_algorithms["SHA256WITHDSA"] = NistObjectIdentifiers.DsaWithSha256;
            m_algorithms["SHA384WITHDSA"] = NistObjectIdentifiers.DsaWithSha384;
            m_algorithms["SHA512WITHDSA"] = NistObjectIdentifiers.DsaWithSha512;
            m_algorithms["SHA3-224WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_224;
            m_algorithms["SHA3-256WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_256;
            m_algorithms["SHA3-384WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_384;
            m_algorithms["SHA3-512WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_512;
            m_algorithms["SHA3-224WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_224;
            m_algorithms["SHA3-256WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_256;
            m_algorithms["SHA3-384WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_384;
            m_algorithms["SHA3-512WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_512;
            m_algorithms["SHA3-224WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
            m_algorithms["SHA3-256WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
            m_algorithms["SHA3-384WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
            m_algorithms["SHA3-512WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;
            m_algorithms["SHA3-224WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
            m_algorithms["SHA3-256WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
            m_algorithms["SHA3-384WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
            m_algorithms["SHA3-512WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;
            m_algorithms["SHA1WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha1;
            m_algorithms["ECDSAWITHSHA1"] = X9ObjectIdentifiers.ECDsaWithSha1;
            m_algorithms["SHA224WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha224;
            m_algorithms["SHA256WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha256;
            m_algorithms["SHA384WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha384;
            m_algorithms["SHA512WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha512;
            m_algorithms["GOST3411WITHGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            m_algorithms["GOST3411WITHGOST3410-94"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            m_algorithms["GOST3411WITHECGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            m_algorithms["GOST3411WITHECGOST3410-2001"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            m_algorithms["GOST3411WITHGOST3410-2001"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            m_algorithms["GOST3411WITHECGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            m_algorithms["GOST3411WITHECGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            m_algorithms["GOST3411WITHGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            m_algorithms["GOST3411WITHGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            m_algorithms["GOST3411-2012-256WITHECGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            m_algorithms["GOST3411-2012-512WITHECGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            m_algorithms["GOST3411-2012-256WITHGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            m_algorithms["GOST3411-2012-512WITHGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;

            // NOTE: Not in bc-java
            m_algorithms["GOST3411-2012-256WITHECGOST3410"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            m_algorithms["GOST3411-2012-512WITHECGOST3410"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;

            m_algorithms["SHA1WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_1;
            m_algorithms["SHA224WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_224;
            m_algorithms["SHA256WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_256;
            m_algorithms["SHA384WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_384;
            m_algorithms["SHA512WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_512;
            m_algorithms["SHA3-512WITHSPHINCS256"] = BCObjectIdentifiers.sphincs256_with_SHA3_512;
            m_algorithms["SHA512WITHSPHINCS256"] = BCObjectIdentifiers.sphincs256_with_SHA512;

            m_algorithms["SHA1WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA1;
            m_algorithms["RIPEMD160WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;
            m_algorithms["SHA224WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA224;
            m_algorithms["SHA256WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA256;
            m_algorithms["SHA384WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA384;
            m_algorithms["SHA512WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA512;
            m_algorithms["SHA3-224WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_224;
            m_algorithms["SHA3-256WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_256;
            m_algorithms["SHA3-384WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_384;
            m_algorithms["SHA3-512WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_512;

            m_algorithms["ED25519"] = EdECObjectIdentifiers.id_Ed25519;
            m_algorithms["ED448"] = EdECObjectIdentifiers.id_Ed448;

            // RFC 8702
            m_algorithms["SHAKE128WITHRSAPSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128;
            m_algorithms["SHAKE256WITHRSAPSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256;
            m_algorithms["SHAKE128WITHRSASSA-PSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128;
            m_algorithms["SHAKE256WITHRSASSA-PSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256;
            m_algorithms["SHAKE128WITHECDSA"] = CmsObjectIdentifiers.id_ecdsa_with_shake128;
            m_algorithms["SHAKE256WITHECDSA"] = CmsObjectIdentifiers.id_ecdsa_with_shake256;

            //m_algorithms["RIPEMD160WITHSM2"] = GMObjectIdentifiers.sm2sign_with_rmd160;
            //m_algorithms["SHA1WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha1;
            //m_algorithms["SHA224WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha224;
            m_algorithms["SHA256WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha256;
            //m_algorithms["SHA384WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha384;
            //m_algorithms["SHA512WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha512;
            m_algorithms["SM3WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sm3;

            m_algorithms["SHA256WITHXMSS"] = BCObjectIdentifiers.xmss_SHA256ph;
            m_algorithms["SHA512WITHXMSS"] = BCObjectIdentifiers.xmss_SHA512ph;
            m_algorithms["SHAKE128WITHXMSS"] = BCObjectIdentifiers.xmss_SHAKE128ph;
            m_algorithms["SHAKE256WITHXMSS"] = BCObjectIdentifiers.xmss_SHAKE256ph;

            m_algorithms["SHA256WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHA256ph;
            m_algorithms["SHA512WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHA512ph;
            m_algorithms["SHAKE128WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
            m_algorithms["SHAKE256WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHAKE256ph;

            m_algorithms["SHA256WITHXMSS-SHA256"] = BCObjectIdentifiers.xmss_SHA256ph;
            m_algorithms["SHA512WITHXMSS-SHA512"] = BCObjectIdentifiers.xmss_SHA512ph;
            m_algorithms["SHAKE128WITHXMSS-SHAKE128"] = BCObjectIdentifiers.xmss_SHAKE128ph;
            m_algorithms["SHAKE256WITHXMSS-SHAKE256"] = BCObjectIdentifiers.xmss_SHAKE256ph;

            m_algorithms["SHA256WITHXMSSMT-SHA256"] = BCObjectIdentifiers.xmss_mt_SHA256ph;
            m_algorithms["SHA512WITHXMSSMT-SHA512"] = BCObjectIdentifiers.xmss_mt_SHA512ph;
            m_algorithms["SHAKE128WITHXMSSMT-SHAKE128"] = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
            m_algorithms["SHAKE256WITHXMSSMT-SHAKE256"] = BCObjectIdentifiers.xmss_mt_SHAKE256ph;

            m_algorithms["LMS"] = PkcsObjectIdentifiers.IdAlgHssLmsHashsig;

            m_algorithms["XMSS"] = IsaraObjectIdentifiers.id_alg_xmss;
            m_algorithms["XMSS-SHA256"] = BCObjectIdentifiers.xmss_SHA256;
            m_algorithms["XMSS-SHA512"] = BCObjectIdentifiers.xmss_SHA512;
            m_algorithms["XMSS-SHAKE128"] = BCObjectIdentifiers.xmss_SHAKE128;
            m_algorithms["XMSS-SHAKE256"] = BCObjectIdentifiers.xmss_SHAKE256;

            m_algorithms["XMSSMT"] = IsaraObjectIdentifiers.id_alg_xmssmt;
            m_algorithms["XMSSMT-SHA256"] = BCObjectIdentifiers.xmss_mt_SHA256;
            m_algorithms["XMSSMT-SHA512"] = BCObjectIdentifiers.xmss_mt_SHA512;
            m_algorithms["XMSSMT-SHAKE128"] = BCObjectIdentifiers.xmss_mt_SHAKE128;
            m_algorithms["XMSSMT-SHAKE256"] = BCObjectIdentifiers.xmss_mt_SHAKE256;

            m_algorithms["SPHINCS+"] = BCObjectIdentifiers.sphincsPlus;
            m_algorithms["SPHINCSPLUS"] = BCObjectIdentifiers.sphincsPlus;

            m_algorithms["DILITHIUM2"] = BCObjectIdentifiers.dilithium2;
            m_algorithms["DILITHIUM3"] = BCObjectIdentifiers.dilithium3;
            m_algorithms["DILITHIUM5"] = BCObjectIdentifiers.dilithium5;
            m_algorithms["DILITHIUM2-AES"] = BCObjectIdentifiers.dilithium2_aes;
            m_algorithms["DILITHIUM3-AES"] = BCObjectIdentifiers.dilithium3_aes;
            m_algorithms["DILITHIUM5-AES"] = BCObjectIdentifiers.dilithium5_aes;

            m_algorithms["FALCON-512"] = BCObjectIdentifiers.falcon_512;
            m_algorithms["FALCON-1024"] = BCObjectIdentifiers.falcon_1024;

            m_algorithms["PICNIC"] = BCObjectIdentifiers.picnic_signature;
            m_algorithms["SHA512WITHPICNIC"] = BCObjectIdentifiers.picnic_with_sha512;
            m_algorithms["SHA3-512WITHPICNIC"] = BCObjectIdentifiers.picnic_with_sha3_512;
            m_algorithms["SHAKE256WITHPICNIC"] = BCObjectIdentifiers.picnic_with_shake256;

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
            m_noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha224);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha256);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha384);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha512);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_224);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_256);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_384);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_512);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512);

            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA224);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA256);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA384);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA512);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_224);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_256);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_384);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_512);

            //
            // RFC 4491
            //
            m_noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            m_noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            m_noParams.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            m_noParams.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            //
            // SPHINCS-256
            //
            m_noParams.Add(BCObjectIdentifiers.sphincs256_with_SHA512);
            m_noParams.Add(BCObjectIdentifiers.sphincs256_with_SHA3_512);

            //
            // SPHINCS-PLUS
            //
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
            m_noParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);

            //
            // Dilithium
            //
            m_noParams.Add(BCObjectIdentifiers.dilithium);
            m_noParams.Add(BCObjectIdentifiers.dilithium2);
            m_noParams.Add(BCObjectIdentifiers.dilithium3);
            m_noParams.Add(BCObjectIdentifiers.dilithium5);
            m_noParams.Add(BCObjectIdentifiers.dilithium2_aes);
            m_noParams.Add(BCObjectIdentifiers.dilithium3_aes);
            m_noParams.Add(BCObjectIdentifiers.dilithium5_aes);

            //
            // Falcon
            //
            m_noParams.Add(BCObjectIdentifiers.falcon);
            m_noParams.Add(BCObjectIdentifiers.falcon_512);
            m_noParams.Add(BCObjectIdentifiers.falcon_1024);

            //
            // Picnic
            //
            m_noParams.Add(BCObjectIdentifiers.picnic_signature);
            m_noParams.Add(BCObjectIdentifiers.picnic_with_sha512);
            m_noParams.Add(BCObjectIdentifiers.picnic_with_sha3_512);
            m_noParams.Add(BCObjectIdentifiers.picnic_with_shake256);

            //
            // XMSS
            //
            m_noParams.Add(BCObjectIdentifiers.xmss_SHA256ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_SHA512ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_SHAKE128ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_SHAKE256ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHA256ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHA512ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE128ph);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE256ph);

            m_noParams.Add(BCObjectIdentifiers.xmss_SHA256);
            m_noParams.Add(BCObjectIdentifiers.xmss_SHA512);
            m_noParams.Add(BCObjectIdentifiers.xmss_SHAKE128);
            m_noParams.Add(BCObjectIdentifiers.xmss_SHAKE256);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHA256);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHA512);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE128);
            m_noParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE256);

            m_noParams.Add(IsaraObjectIdentifiers.id_alg_xmss);
            m_noParams.Add(IsaraObjectIdentifiers.id_alg_xmssmt);

            //
            // qTESLA
            //
            m_noParams.Add(BCObjectIdentifiers.qTESLA_p_I);
            m_noParams.Add(BCObjectIdentifiers.qTESLA_p_III);

            //
            // SM2
            //
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_rmd160);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha1);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha224);
            m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha256);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha384);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha512);
            m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sm3);

            // EdDSA
            m_noParams.Add(EdECObjectIdentifiers.id_Ed25519);
            m_noParams.Add(EdECObjectIdentifiers.id_Ed448);

            // RFC 8702
            m_noParams.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            m_noParams.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            m_noParams.Add(CmsObjectIdentifiers.id_ecdsa_with_shake128);
            m_noParams.Add(CmsObjectIdentifiers.id_ecdsa_with_shake256);

            //
            // PKCS 1.5 encrypted  algorithms
            //
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            m_pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            m_pkcs15RsaEncryption.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            m_pkcs15RsaEncryption.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            m_pkcs15RsaEncryption.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
            m_pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            m_pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            m_pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            m_pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

            //
            // explicit params
            //
            AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            m_parameters["SHA1WITHRSAANDMGF1"] = CreatePssParams(sha1AlgId, 20);

            AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            m_parameters["SHA224WITHRSAANDMGF1"] = CreatePssParams(sha224AlgId, 28);

            AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            m_parameters["SHA256WITHRSAANDMGF1"] = CreatePssParams(sha256AlgId, 32);

            AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            m_parameters["SHA384WITHRSAANDMGF1"] = CreatePssParams(sha384AlgId, 48);

            AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            m_parameters["SHA512WITHRSAANDMGF1"] = CreatePssParams(sha512AlgId, 64);

            AlgorithmIdentifier sha3_224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_224, DerNull.Instance);
            m_parameters["SHA3-224WITHRSAANDMGF1"] = CreatePssParams(sha3_224AlgId, 28);

            AlgorithmIdentifier sha3_256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_256, DerNull.Instance);
            m_parameters["SHA3-256WITHRSAANDMGF1"] = CreatePssParams(sha3_256AlgId, 32);

            AlgorithmIdentifier sha3_384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_384, DerNull.Instance);
            m_parameters["SHA3-384WITHRSAANDMGF1"] = CreatePssParams(sha3_384AlgId, 48);

            AlgorithmIdentifier sha3_512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_512, DerNull.Instance);
            m_parameters["SHA3-512WITHRSAANDMGF1"] = CreatePssParams(sha3_512AlgId, 64);

            //
            // digests
            //
            m_digestOids[PkcsObjectIdentifiers.Sha224WithRsaEncryption] = NistObjectIdentifiers.IdSha224;
            m_digestOids[PkcsObjectIdentifiers.Sha256WithRsaEncryption] = NistObjectIdentifiers.IdSha256;
            m_digestOids[PkcsObjectIdentifiers.Sha384WithRsaEncryption] = NistObjectIdentifiers.IdSha384;
            m_digestOids[PkcsObjectIdentifiers.Sha512WithRsaEncryption] = NistObjectIdentifiers.IdSha512;
            m_digestOids[PkcsObjectIdentifiers.Sha512_224WithRSAEncryption] = NistObjectIdentifiers.IdSha512_224;
            m_digestOids[PkcsObjectIdentifiers.Sha512_256WithRSAEncryption] = NistObjectIdentifiers.IdSha512_256;
            m_digestOids[NistObjectIdentifiers.DsaWithSha224] = NistObjectIdentifiers.IdSha224;
            m_digestOids[NistObjectIdentifiers.DsaWithSha256] = NistObjectIdentifiers.IdSha256;
            m_digestOids[NistObjectIdentifiers.DsaWithSha384] = NistObjectIdentifiers.IdSha384;
            m_digestOids[NistObjectIdentifiers.DsaWithSha512] = NistObjectIdentifiers.IdSha512;
            m_digestOids[NistObjectIdentifiers.IdDsaWithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            m_digestOids[NistObjectIdentifiers.IdDsaWithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            m_digestOids[NistObjectIdentifiers.IdDsaWithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            m_digestOids[NistObjectIdentifiers.IdDsaWithSha3_512] = NistObjectIdentifiers.IdSha3_512;
            m_digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            m_digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            m_digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            m_digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_512] = NistObjectIdentifiers.IdSha3_512;
            m_digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            m_digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            m_digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            m_digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512] = NistObjectIdentifiers.IdSha3_512;

            m_digestOids[PkcsObjectIdentifiers.MD2WithRsaEncryption] = PkcsObjectIdentifiers.MD2;
            m_digestOids[PkcsObjectIdentifiers.MD4WithRsaEncryption] = PkcsObjectIdentifiers.MD4;
            m_digestOids[PkcsObjectIdentifiers.MD5WithRsaEncryption] = PkcsObjectIdentifiers.MD5;
            m_digestOids[PkcsObjectIdentifiers.Sha1WithRsaEncryption] = OiwObjectIdentifiers.IdSha1;
            m_digestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128] = TeleTrusTObjectIdentifiers.RipeMD128;
            m_digestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160] = TeleTrusTObjectIdentifiers.RipeMD160;
            m_digestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256] = TeleTrusTObjectIdentifiers.RipeMD256;
            m_digestOids[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94] = CryptoProObjectIdentifiers.GostR3411;
            m_digestOids[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001] = CryptoProObjectIdentifiers.GostR3411;
            m_digestOids[RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
            m_digestOids[RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;

            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_128s_r3] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_128f_r3] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_192s_r3] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_192f_r3] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_256s_r3] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_256f_r3] = NistObjectIdentifiers.IdShake256;

            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple] = NistObjectIdentifiers.IdSha256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple] = NistObjectIdentifiers.IdShake256;
            m_digestOids[BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple] = NistObjectIdentifiers.IdShake256;

            //m_digestOids[GMObjectIdentifiers.sm2sign_with_rmd160] = TeleTrusTObjectIdentifiers.RipeMD160;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha1] = OiwObjectIdentifiers.IdSha1;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha224] = NistObjectIdentifiers.IdSha224;
            m_digestOids[GMObjectIdentifiers.sm2sign_with_sha256] = NistObjectIdentifiers.IdSha256;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha384] = NistObjectIdentifiers.IdSha384;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha512] = NistObjectIdentifiers.IdSha512;
            m_digestOids[GMObjectIdentifiers.sm2sign_with_sm3] = GMObjectIdentifiers.sm3;

            m_digestOids[CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128] = NistObjectIdentifiers.IdShake128;
            m_digestOids[CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256] = NistObjectIdentifiers.IdShake256;
            m_digestOids[CmsObjectIdentifiers.id_ecdsa_with_shake128] = NistObjectIdentifiers.IdShake128;
            m_digestOids[CmsObjectIdentifiers.id_ecdsa_with_shake256] = NistObjectIdentifiers.IdShake256;
        }

        private static RsassaPssParameters CreatePssParams(AlgorithmIdentifier hashAlgID, int saltSize)
        {
            return new RsassaPssParameters(
                hashAlgID,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgID),
                new DerInteger(saltSize),
                new DerInteger(1));
        }

        // TODO[api] Make virtual
        public AlgorithmIdentifier Find(string sigAlgName)
        {
            if (!m_algorithms.TryGetValue(sigAlgName, out var sigAlgOid))
                throw new ArgumentException("Unknown signature type requested: " + sigAlgName, nameof(sigAlgName));

            AlgorithmIdentifier sigAlgID;
            if (m_noParams.Contains(sigAlgOid))
            {
                sigAlgID = new AlgorithmIdentifier(sigAlgOid);
            }
            else if (m_parameters.TryGetValue(sigAlgName, out var parameters))
            {
                sigAlgID = new AlgorithmIdentifier(sigAlgOid, parameters);
            }
            else
            {
                sigAlgID = new AlgorithmIdentifier(sigAlgOid, DerNull.Instance);
            }
            return sigAlgID;
        }
    }

    // TODO[api] Create API for this
    public class DefaultDigestAlgorithmIdentifierFinder
    {
        public static readonly DefaultDigestAlgorithmIdentifierFinder Instance =
            new DefaultDigestAlgorithmIdentifierFinder();

        private static readonly Dictionary<DerObjectIdentifier, DerObjectIdentifier> m_digestOids =
            new Dictionary<DerObjectIdentifier, DerObjectIdentifier>();
        private static readonly Dictionary<string, DerObjectIdentifier> m_digestNameToOids =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, AlgorithmIdentifier> m_digestOidToAlgIDs =
            new Dictionary<DerObjectIdentifier, AlgorithmIdentifier>();

        // signatures that use SHAKE-256
        private static readonly HashSet<DerObjectIdentifier> m_shake256Oids = new HashSet<DerObjectIdentifier>();

        static DefaultDigestAlgorithmIdentifierFinder()
        {
            //
            // digests
            //
            m_digestOids.Add(OiwObjectIdentifiers.DsaWithSha1, OiwObjectIdentifiers.IdSha1);
            m_digestOids.Add(OiwObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            m_digestOids.Add(OiwObjectIdentifiers.MD4WithRsa, PkcsObjectIdentifiers.MD4);
            m_digestOids.Add(OiwObjectIdentifiers.MD5WithRsa, PkcsObjectIdentifiers.MD5);
            m_digestOids.Add(OiwObjectIdentifiers.Sha1WithRsa, OiwObjectIdentifiers.IdSha1);

            m_digestOids.Add(PkcsObjectIdentifiers.Sha224WithRsaEncryption, NistObjectIdentifiers.IdSha224);
            m_digestOids.Add(PkcsObjectIdentifiers.Sha256WithRsaEncryption, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(PkcsObjectIdentifiers.Sha384WithRsaEncryption, NistObjectIdentifiers.IdSha384);
            m_digestOids.Add(PkcsObjectIdentifiers.Sha512WithRsaEncryption, NistObjectIdentifiers.IdSha512);
            m_digestOids.Add(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption, NistObjectIdentifiers.IdSha512_224);
            m_digestOids.Add(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption, NistObjectIdentifiers.IdSha512_256);
            m_digestOids.Add(PkcsObjectIdentifiers.MD2WithRsaEncryption, PkcsObjectIdentifiers.MD2);
            m_digestOids.Add(PkcsObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            m_digestOids.Add(PkcsObjectIdentifiers.MD5WithRsaEncryption, PkcsObjectIdentifiers.MD5);
            m_digestOids.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption, OiwObjectIdentifiers.IdSha1);

            m_digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha1, OiwObjectIdentifiers.IdSha1);
            m_digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha224, NistObjectIdentifiers.IdSha224);
            m_digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha256, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha384, NistObjectIdentifiers.IdSha384);
            m_digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha512, NistObjectIdentifiers.IdSha512);
            m_digestOids.Add(X9ObjectIdentifiers.IdDsaWithSha1, OiwObjectIdentifiers.IdSha1);

            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA1, OiwObjectIdentifiers.IdSha1);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA224, NistObjectIdentifiers.IdSha224);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA256, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA384, NistObjectIdentifiers.IdSha384);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA512, NistObjectIdentifiers.IdSha512);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_224, NistObjectIdentifiers.IdSha3_224);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_256, NistObjectIdentifiers.IdSha3_256);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_384, NistObjectIdentifiers.IdSha3_384);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_512, NistObjectIdentifiers.IdSha3_512);
            m_digestOids.Add(BsiObjectIdentifiers.ecdsa_plain_RIPEMD160, TeleTrusTObjectIdentifiers.RipeMD160);

            m_digestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, OiwObjectIdentifiers.IdSha1);
            m_digestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, NistObjectIdentifiers.IdSha224);
            m_digestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, NistObjectIdentifiers.IdSha384);
            m_digestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, NistObjectIdentifiers.IdSha512);

            m_digestOids.Add(NistObjectIdentifiers.DsaWithSha224, NistObjectIdentifiers.IdSha224);
            m_digestOids.Add(NistObjectIdentifiers.DsaWithSha256, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(NistObjectIdentifiers.DsaWithSha384, NistObjectIdentifiers.IdSha384);
            m_digestOids.Add(NistObjectIdentifiers.DsaWithSha512, NistObjectIdentifiers.IdSha512);

            m_digestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, NistObjectIdentifiers.IdSha3_224);
            m_digestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, NistObjectIdentifiers.IdSha3_256);
            m_digestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, NistObjectIdentifiers.IdSha3_384);
            m_digestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, NistObjectIdentifiers.IdSha3_512);
            m_digestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_224, NistObjectIdentifiers.IdSha3_224);
            m_digestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_256, NistObjectIdentifiers.IdSha3_256);
            m_digestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_384, NistObjectIdentifiers.IdSha3_384);
            m_digestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_512, NistObjectIdentifiers.IdSha3_512);
            m_digestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224, NistObjectIdentifiers.IdSha3_224);
            m_digestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256, NistObjectIdentifiers.IdSha3_256);
            m_digestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384, NistObjectIdentifiers.IdSha3_384);
            m_digestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512, NistObjectIdentifiers.IdSha3_512);

            m_digestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, TeleTrusTObjectIdentifiers.RipeMD128);
            m_digestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, TeleTrusTObjectIdentifiers.RipeMD160);
            m_digestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, TeleTrusTObjectIdentifiers.RipeMD256);

            m_digestOids.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, CryptoProObjectIdentifiers.GostR3411);
            m_digestOids.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, CryptoProObjectIdentifiers.GostR3411);
            m_digestOids.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            m_digestOids.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

            m_digestOids.Add(BCObjectIdentifiers.sphincs256_with_SHA3_512, NistObjectIdentifiers.IdSha3_512);
            m_digestOids.Add(BCObjectIdentifiers.sphincs256_with_SHA512, NistObjectIdentifiers.IdSha512);

            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, NistObjectIdentifiers.IdShake256);

            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, NistObjectIdentifiers.IdSha256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, NistObjectIdentifiers.IdShake256);

            m_digestOids.Add(BCObjectIdentifiers.falcon, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.falcon_512, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.falcon_1024, NistObjectIdentifiers.IdShake256);

            m_digestOids.Add(BCObjectIdentifiers.picnic_signature, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(BCObjectIdentifiers.picnic_with_sha512, NistObjectIdentifiers.IdSha512);
            m_digestOids.Add(BCObjectIdentifiers.picnic_with_sha3_512, NistObjectIdentifiers.IdSha3_512);
            m_digestOids.Add(BCObjectIdentifiers.picnic_with_shake256, NistObjectIdentifiers.IdShake256);

            //m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_rmd160, TeleTrusTObjectIdentifiers.RipeMD160);
            //m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_sha1, OiwObjectIdentifiers.IdSha1);
            //m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_sha224, NistObjectIdentifiers.IdSha224);
            m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_sha256, NistObjectIdentifiers.IdSha256);
            //m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_sha384, NistObjectIdentifiers.IdSha384);
            //m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_sha512, NistObjectIdentifiers.IdSha512);
            m_digestOids.Add(GMObjectIdentifiers.sm2sign_with_sm3, GMObjectIdentifiers.sm3);

            m_digestOids.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128, NistObjectIdentifiers.IdShake128);
            m_digestOids.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256, NistObjectIdentifiers.IdShake256);
            m_digestOids.Add(CmsObjectIdentifiers.id_ecdsa_with_shake128, NistObjectIdentifiers.IdShake128);
            m_digestOids.Add(CmsObjectIdentifiers.id_ecdsa_with_shake256, NistObjectIdentifiers.IdShake256);

            m_digestNameToOids.Add("SHA-1", OiwObjectIdentifiers.IdSha1);
            m_digestNameToOids.Add("SHA-224", NistObjectIdentifiers.IdSha224);
            m_digestNameToOids.Add("SHA-256", NistObjectIdentifiers.IdSha256);
            m_digestNameToOids.Add("SHA-384", NistObjectIdentifiers.IdSha384);
            m_digestNameToOids.Add("SHA-512", NistObjectIdentifiers.IdSha512);
            m_digestNameToOids.Add("SHA-512-224", NistObjectIdentifiers.IdSha512_224);
            m_digestNameToOids.Add("SHA-512/224", NistObjectIdentifiers.IdSha512_224);
            m_digestNameToOids.Add("SHA-512(224)", NistObjectIdentifiers.IdSha512_224);
            m_digestNameToOids.Add("SHA-512-256", NistObjectIdentifiers.IdSha512_256);
            m_digestNameToOids.Add("SHA-512/256", NistObjectIdentifiers.IdSha512_256);
            m_digestNameToOids.Add("SHA-512(256)", NistObjectIdentifiers.IdSha512_256);

            m_digestNameToOids.Add("SHA1", OiwObjectIdentifiers.IdSha1);
            m_digestNameToOids.Add("SHA224", NistObjectIdentifiers.IdSha224);
            m_digestNameToOids.Add("SHA256", NistObjectIdentifiers.IdSha256);
            m_digestNameToOids.Add("SHA384", NistObjectIdentifiers.IdSha384);
            m_digestNameToOids.Add("SHA512", NistObjectIdentifiers.IdSha512);
            m_digestNameToOids.Add("SHA512-224", NistObjectIdentifiers.IdSha512_224);
            m_digestNameToOids.Add("SHA512/224", NistObjectIdentifiers.IdSha512_224);
            m_digestNameToOids.Add("SHA512(224)", NistObjectIdentifiers.IdSha512_224);
            m_digestNameToOids.Add("SHA512-256", NistObjectIdentifiers.IdSha512_256);
            m_digestNameToOids.Add("SHA512/256", NistObjectIdentifiers.IdSha512_256);
            m_digestNameToOids.Add("SHA512(256)", NistObjectIdentifiers.IdSha512_256);

            m_digestNameToOids.Add("SHA3-224", NistObjectIdentifiers.IdSha3_224);
            m_digestNameToOids.Add("SHA3-256", NistObjectIdentifiers.IdSha3_256);
            m_digestNameToOids.Add("SHA3-384", NistObjectIdentifiers.IdSha3_384);
            m_digestNameToOids.Add("SHA3-512", NistObjectIdentifiers.IdSha3_512);

            m_digestNameToOids.Add("SHAKE128", NistObjectIdentifiers.IdShake128);
            m_digestNameToOids.Add("SHAKE256", NistObjectIdentifiers.IdShake256);
            m_digestNameToOids.Add("SHAKE-128", NistObjectIdentifiers.IdShake128);
            m_digestNameToOids.Add("SHAKE-256", NistObjectIdentifiers.IdShake256);

            m_digestNameToOids.Add("GOST3411", CryptoProObjectIdentifiers.GostR3411);
            m_digestNameToOids.Add("GOST3411-2012-256", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            m_digestNameToOids.Add("GOST3411-2012-512", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

            m_digestNameToOids.Add("MD2", PkcsObjectIdentifiers.MD2);
            m_digestNameToOids.Add("MD4", PkcsObjectIdentifiers.MD4);
            m_digestNameToOids.Add("MD5", PkcsObjectIdentifiers.MD5);

            m_digestNameToOids.Add("RIPEMD128", TeleTrusTObjectIdentifiers.RipeMD128);
            m_digestNameToOids.Add("RIPEMD160", TeleTrusTObjectIdentifiers.RipeMD160);
            m_digestNameToOids.Add("RIPEMD256", TeleTrusTObjectIdentifiers.RipeMD256);

            m_digestNameToOids.Add("SM3", GMObjectIdentifiers.sm3);

            // IETF RFC 3370
            AddDigestAlgID(OiwObjectIdentifiers.IdSha1, true);
            // IETF RFC 5754
            AddDigestAlgID(NistObjectIdentifiers.IdSha224, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha256, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha384, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha512, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha512_224, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha512_256, false);

            // NIST CSOR
            AddDigestAlgID(NistObjectIdentifiers.IdSha3_224, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha3_256, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha3_384, false);
            AddDigestAlgID(NistObjectIdentifiers.IdSha3_512, false);

            // RFC 8702
            AddDigestAlgID(NistObjectIdentifiers.IdShake128, false);
            AddDigestAlgID(NistObjectIdentifiers.IdShake256, false);

            // RFC 4357
            AddDigestAlgID(CryptoProObjectIdentifiers.GostR3411, true);

            // draft-deremin-rfc4491
            AddDigestAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, false);
            AddDigestAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, false);

            // IETF RFC 1319
            AddDigestAlgID(PkcsObjectIdentifiers.MD2, true);
            // IETF RFC 1320
            AddDigestAlgID(PkcsObjectIdentifiers.MD4, true);
            // IETF RFC 1321
            AddDigestAlgID(PkcsObjectIdentifiers.MD5, true);

            // found no standard which specified the handle of AlgorithmIdentifier.parameters,
            // so let it as before.
            AddDigestAlgID(TeleTrusTObjectIdentifiers.RipeMD128, true);
            AddDigestAlgID(TeleTrusTObjectIdentifiers.RipeMD160, true);
            AddDigestAlgID(TeleTrusTObjectIdentifiers.RipeMD256, true);

            m_shake256Oids.Add(EdECObjectIdentifiers.id_Ed448);

            m_shake256Oids.Add(BCObjectIdentifiers.dilithium2);
            m_shake256Oids.Add(BCObjectIdentifiers.dilithium3);
            m_shake256Oids.Add(BCObjectIdentifiers.dilithium5);
            m_shake256Oids.Add(BCObjectIdentifiers.dilithium2_aes);
            m_shake256Oids.Add(BCObjectIdentifiers.dilithium3_aes);
            m_shake256Oids.Add(BCObjectIdentifiers.dilithium5_aes);

            m_shake256Oids.Add(BCObjectIdentifiers.falcon_512);
            m_shake256Oids.Add(BCObjectIdentifiers.falcon_1024);
        }

        private static void AddDigestAlgID(DerObjectIdentifier oid, bool withNullParams) =>
            m_digestOidToAlgIDs.Add(oid, new AlgorithmIdentifier(oid, withNullParams ? DerNull.Instance : null));

        // TODO[api] Make virtual
        public AlgorithmIdentifier Find(AlgorithmIdentifier sigAlgId)
        {
            DerObjectIdentifier sigAlgOid = sigAlgId.Algorithm;

            if (m_shake256Oids.Contains(sigAlgOid))
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256Len, new DerInteger(512));

            DerObjectIdentifier digAlgOid;
            if (PkcsObjectIdentifiers.IdRsassaPss.Equals(sigAlgOid))
            {
                digAlgOid = RsassaPssParameters.GetInstance(sigAlgId.Parameters).HashAlgorithm.Algorithm;
            }
            else if (EdECObjectIdentifiers.id_Ed25519.Equals(sigAlgOid))
            {
                digAlgOid = NistObjectIdentifiers.IdSha512;
            }
            else if (PkcsObjectIdentifiers.IdAlgHssLmsHashsig.Equals(sigAlgOid))
            {
                digAlgOid = NistObjectIdentifiers.IdSha256;
            }
            else
            {
                digAlgOid = CollectionUtilities.GetValueOrNull(m_digestOids, sigAlgOid);
            }

            return Find(digAlgOid);
        }

        public virtual AlgorithmIdentifier Find(DerObjectIdentifier digAlgOid)
        {
            if (digAlgOid == null)
                throw new ArgumentNullException(nameof(digAlgOid));

            if (m_digestOidToAlgIDs.TryGetValue(digAlgOid, out var digAlgID))
                return digAlgID;

            return new AlgorithmIdentifier(digAlgOid);
        }

        // TODO[api] Make virtual
        public AlgorithmIdentifier Find(string digAlgName)
        {
            if (m_digestNameToOids.TryGetValue(digAlgName, out var oid))
                return Find(oid);

            try
            {
                return Find(new DerObjectIdentifier(digAlgName));
            }
            catch (Exception)
            {
                // ignore - tried it but it didn't work...
            }

            return null;
        }
    }

    public abstract class CmsSignedGenerator
    {
        /**
        * Default type for the signed data.
        */
        public static readonly string Data = CmsObjectIdentifiers.Data.Id;

        public static readonly string DigestSha1 = OiwObjectIdentifiers.IdSha1.Id;
        public static readonly string DigestSha224 = NistObjectIdentifiers.IdSha224.Id;
        public static readonly string DigestSha256 = NistObjectIdentifiers.IdSha256.Id;
        public static readonly string DigestSha384 = NistObjectIdentifiers.IdSha384.Id;
        public static readonly string DigestSha512 = NistObjectIdentifiers.IdSha512.Id;
        public static readonly string DigestSha512_224 = NistObjectIdentifiers.IdSha512_224.Id;
        public static readonly string DigestSha512_256 = NistObjectIdentifiers.IdSha512_256.Id;
        public static readonly string DigestMD5 = PkcsObjectIdentifiers.MD5.Id;
        public static readonly string DigestGost3411 = CryptoProObjectIdentifiers.GostR3411.Id;
        public static readonly string DigestRipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128.Id;
        public static readonly string DigestRipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160.Id;
        public static readonly string DigestRipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256.Id;

        public static readonly string EncryptionRsa = PkcsObjectIdentifiers.RsaEncryption.Id;
        public static readonly string EncryptionDsa = X9ObjectIdentifiers.IdDsaWithSha1.Id;
        public static readonly string EncryptionECDsa = X9ObjectIdentifiers.ECDsaWithSha1.Id;
        public static readonly string EncryptionRsaPss = PkcsObjectIdentifiers.IdRsassaPss.Id;
        public static readonly string EncryptionGost3410 = CryptoProObjectIdentifiers.GostR3410x94.Id;
        public static readonly string EncryptionECGost3410 = CryptoProObjectIdentifiers.GostR3410x2001.Id;
        public static readonly string EncryptionECGost3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id;
        public static readonly string EncryptionECGost3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Id;

        internal List<Asn1Encodable> _certs = new List<Asn1Encodable>();
        internal List<Asn1Encodable> _crls = new List<Asn1Encodable>();
        internal IList<SignerInformation> _signers = new List<SignerInformation>();
        internal IDictionary<string, byte[]> m_digests =
            new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        internal bool _useDerForCerts = false;
        internal bool _useDerForCrls = false;

        protected readonly SecureRandom m_random;

        protected CmsSignedGenerator()
            : this(CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        protected CmsSignedGenerator(SecureRandom random)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_random = random;
        }

        internal protected virtual IDictionary<CmsAttributeTableParameter, object> GetBaseParameters(
            DerObjectIdentifier contentType, AlgorithmIdentifier digAlgId, byte[] hash)
        {
            var param = new Dictionary<CmsAttributeTableParameter, object>();

            if (contentType != null)
            {
                param[CmsAttributeTableParameter.ContentType] = contentType;
            }

            param[CmsAttributeTableParameter.DigestAlgorithmIdentifier] = digAlgId;
            param[CmsAttributeTableParameter.Digest] = hash.Clone();

            return param;
        }

        internal protected virtual Asn1Set GetAttributeSet(
            Asn1.Cms.AttributeTable attr)
        {
            return attr == null
                ? null
                : DerSet.FromVector(attr.ToAsn1EncodableVector());
        }

        public void AddAttributeCertificate(X509V2AttributeCertificate attrCert)
        {
            _certs.Add(new DerTaggedObject(false, 2, attrCert.AttributeCertificate));
        }

        public void AddAttributeCertificates(IStore<X509V2AttributeCertificate> attrCertStore)
        {
            _certs.AddRange(CmsUtilities.GetAttributeCertificatesFromStore(attrCertStore));
        }

        public void AddCertificate(X509Certificate cert)
        {
            _certs.Add(cert.CertificateStructure);
        }

        public void AddCertificates(IStore<X509Certificate> certStore)
        {
            _certs.AddRange(CmsUtilities.GetCertificatesFromStore(certStore));
        }

        public void AddCrl(X509Crl crl)
        {
            _crls.Add(crl.CertificateList);
        }

        public void AddCrls(IStore<X509Crl> crlStore)
        {
            _crls.AddRange(CmsUtilities.GetCrlsFromStore(crlStore));
        }

        public void AddOtherRevocationInfo(OtherRevocationInfoFormat otherRevocationInfo)
        {
            CmsUtilities.ValidateOtherRevocationInfo(otherRevocationInfo);
            _crls.Add(new DerTaggedObject(false, 1, otherRevocationInfo));
        }

        public void AddOtherRevocationInfos(IStore<OtherRevocationInfoFormat> otherRevocationInfoStore)
        {
            _crls.AddRange(CmsUtilities.GetOtherRevocationInfosFromStore(otherRevocationInfoStore));
        }

        public void AddOtherRevocationInfos(DerObjectIdentifier otherRevInfoFormat,
            IStore<Asn1Encodable> otherRevInfoStore)
        {
            _crls.AddRange(CmsUtilities.GetOtherRevocationInfosFromStore(otherRevInfoStore, otherRevInfoFormat));
        }

        /**
		 * Add a store of precalculated signers to the generator.
		 *
		 * @param signerStore store of signers
		 */
        public void AddSigners(SignerInformationStore signerStore)
        {
            foreach (SignerInformation o in signerStore.GetSigners())
            {
                _signers.Add(o);
                AddSignerCallback(o);
            }
        }

        /**
		 * Return a map of oids and byte arrays representing the digests calculated on the content during
		 * the last generate.
		 *
		 * @return a map of oids (as string objects) and byte[] representing digests.
		 */
        public IDictionary<string, byte[]> GetGeneratedDigests()
        {
            return new Dictionary<string, byte[]>(m_digests, StringComparer.OrdinalIgnoreCase);
        }

        public bool UseDerForCerts
        {
            get { return _useDerForCerts; }
            set { this._useDerForCerts = value; }
        }

        public bool UseDerForCrls
        {
            get { return _useDerForCrls; }
            set { this._useDerForCrls = value; }
        }

        internal virtual void AddSignerCallback(
            SignerInformation si)
        {
        }

        internal static SignerIdentifier GetSignerIdentifier(X509Certificate cert)
        {
            return new SignerIdentifier(CmsUtilities.GetIssuerAndSerialNumber(cert));
        }

        internal static SignerIdentifier GetSignerIdentifier(byte[] subjectKeyIdentifier)
        {
            return new SignerIdentifier(new DerOctetString(subjectKeyIdentifier));
        }
    }
}
