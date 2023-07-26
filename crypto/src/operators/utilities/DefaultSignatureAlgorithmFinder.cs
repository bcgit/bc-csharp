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

namespace Org.BouncyCastle.Operators.Utilities
{
    public class DefaultSignatureAlgorithmFinder
        : ISignatureAlgorithmFinder
    {
        public static readonly DefaultSignatureAlgorithmFinder Instance = new DefaultSignatureAlgorithmFinder();

        private static readonly Dictionary<string, DerObjectIdentifier> Algorithms =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<DerObjectIdentifier> NoParams = new HashSet<DerObjectIdentifier>();
        private static readonly Dictionary<string, Asn1Encodable> Parameters =
            new Dictionary<string, Asn1Encodable>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<DerObjectIdentifier> Pkcs15RsaEncryption = new HashSet<DerObjectIdentifier>();
        private static readonly Dictionary<DerObjectIdentifier, DerObjectIdentifier> DigestOids =
            new Dictionary<DerObjectIdentifier, DerObjectIdentifier>();

        static DefaultSignatureAlgorithmFinder()
        {
            Algorithms["COMPOSITE"] = MiscObjectIdentifiers.id_alg_composite;

            Algorithms["MD2WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            Algorithms["MD2WITHRSA"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            Algorithms["MD5WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;
            Algorithms["MD5WITHRSA"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;
            Algorithms["SHA1WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            Algorithms["SHA-1WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            Algorithms["SHA1WITHRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            Algorithms["SHA-1WITHRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            Algorithms["SHA224WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            Algorithms["SHA-224WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            Algorithms["SHA224WITHRSA"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            Algorithms["SHA-224WITHRSA"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            Algorithms["SHA256WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            Algorithms["SHA-256WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            Algorithms["SHA256WITHRSA"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            Algorithms["SHA-256WITHRSA"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            Algorithms["SHA384WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            Algorithms["SHA-384WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            Algorithms["SHA384WITHRSA"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            Algorithms["SHA-384WITHRSA"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            Algorithms["SHA512WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            Algorithms["SHA-512WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            Algorithms["SHA512WITHRSA"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            Algorithms["SHA-512WITHRSA"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            Algorithms["SHA512(224)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            Algorithms["SHA-512(224)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            Algorithms["SHA512(224)WITHRSA"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            Algorithms["SHA-512(224)WITHRSA"] = PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
            Algorithms["SHA512(256)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            Algorithms["SHA-512(256)WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            Algorithms["SHA512(256)WITHRSA"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            Algorithms["SHA-512(256)WITHRSA"] = PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;
            Algorithms["SHA1WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA224WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA256WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA384WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA512WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA3-224WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA3-256WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA3-384WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["SHA3-512WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            Algorithms["RIPEMD160WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
            Algorithms["RIPEMD160WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
            Algorithms["RIPEMD128WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            Algorithms["RIPEMD128WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            Algorithms["RIPEMD256WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
            Algorithms["RIPEMD256WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
            Algorithms["SHA1WITHDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;
            Algorithms["SHA-1WITHDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;
            Algorithms["DSAWITHSHA1"] = X9ObjectIdentifiers.IdDsaWithSha1;
            Algorithms["SHA224WITHDSA"] = NistObjectIdentifiers.DsaWithSha224;
            Algorithms["SHA256WITHDSA"] = NistObjectIdentifiers.DsaWithSha256;
            Algorithms["SHA384WITHDSA"] = NistObjectIdentifiers.DsaWithSha384;
            Algorithms["SHA512WITHDSA"] = NistObjectIdentifiers.DsaWithSha512;
            Algorithms["SHA3-224WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_224;
            Algorithms["SHA3-256WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_256;
            Algorithms["SHA3-384WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_384;
            Algorithms["SHA3-512WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_512;
            Algorithms["SHA3-224WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_224;
            Algorithms["SHA3-256WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_256;
            Algorithms["SHA3-384WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_384;
            Algorithms["SHA3-512WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_512;
            Algorithms["SHA3-224WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
            Algorithms["SHA3-256WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
            Algorithms["SHA3-384WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
            Algorithms["SHA3-512WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;
            Algorithms["SHA3-224WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
            Algorithms["SHA3-256WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
            Algorithms["SHA3-384WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
            Algorithms["SHA3-512WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;
            Algorithms["SHA1WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha1;
            Algorithms["ECDSAWITHSHA1"] = X9ObjectIdentifiers.ECDsaWithSha1;
            Algorithms["SHA224WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha224;
            Algorithms["SHA256WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha256;
            Algorithms["SHA384WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha384;
            Algorithms["SHA512WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha512;
            Algorithms["GOST3411WITHGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            Algorithms["GOST3411WITHGOST3410-94"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            Algorithms["GOST3411WITHECGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            Algorithms["GOST3411WITHECGOST3410-2001"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            Algorithms["GOST3411WITHGOST3410-2001"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            Algorithms["GOST3411WITHECGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            Algorithms["GOST3411WITHECGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            Algorithms["GOST3411WITHGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            Algorithms["GOST3411WITHGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            Algorithms["GOST3411-2012-256WITHECGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            Algorithms["GOST3411-2012-512WITHECGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            Algorithms["GOST3411-2012-256WITHGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            Algorithms["GOST3411-2012-512WITHGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;

            // NOTE: Not in bc-java
            Algorithms["GOST3411-2012-256WITHECGOST3410"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            Algorithms["GOST3411-2012-512WITHECGOST3410"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;

            Algorithms["SHA1WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_1;
            Algorithms["SHA224WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_224;
            Algorithms["SHA256WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_256;
            Algorithms["SHA384WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_384;
            Algorithms["SHA512WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_512;
            Algorithms["SHA3-512WITHSPHINCS256"] = BCObjectIdentifiers.sphincs256_with_SHA3_512;
            Algorithms["SHA512WITHSPHINCS256"] = BCObjectIdentifiers.sphincs256_with_SHA512;

            Algorithms["SHA1WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA1;
            Algorithms["RIPEMD160WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;
            Algorithms["SHA224WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA224;
            Algorithms["SHA256WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA256;
            Algorithms["SHA384WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA384;
            Algorithms["SHA512WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA512;
            Algorithms["SHA3-224WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_224;
            Algorithms["SHA3-256WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_256;
            Algorithms["SHA3-384WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_384;
            Algorithms["SHA3-512WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA3_512;

            Algorithms["ED25519"] = EdECObjectIdentifiers.id_Ed25519;
            Algorithms["ED448"] = EdECObjectIdentifiers.id_Ed448;

            // RFC 8702
            Algorithms["SHAKE128WITHRSAPSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128;
            Algorithms["SHAKE256WITHRSAPSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256;
            Algorithms["SHAKE128WITHRSASSA-PSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128;
            Algorithms["SHAKE256WITHRSASSA-PSS"] = CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256;
            Algorithms["SHAKE128WITHECDSA"] = CmsObjectIdentifiers.id_ecdsa_with_shake128;
            Algorithms["SHAKE256WITHECDSA"] = CmsObjectIdentifiers.id_ecdsa_with_shake256;

            //m_algorithms["RIPEMD160WITHSM2"] = GMObjectIdentifiers.sm2sign_with_rmd160;
            //m_algorithms["SHA1WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha1;
            //m_algorithms["SHA224WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha224;
            Algorithms["SHA256WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha256;
            //m_algorithms["SHA384WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha384;
            //m_algorithms["SHA512WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha512;
            Algorithms["SM3WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sm3;

            Algorithms["SHA256WITHXMSS"] = BCObjectIdentifiers.xmss_SHA256ph;
            Algorithms["SHA512WITHXMSS"] = BCObjectIdentifiers.xmss_SHA512ph;
            Algorithms["SHAKE128WITHXMSS"] = BCObjectIdentifiers.xmss_SHAKE128ph;
            Algorithms["SHAKE256WITHXMSS"] = BCObjectIdentifiers.xmss_SHAKE256ph;

            Algorithms["SHA256WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHA256ph;
            Algorithms["SHA512WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHA512ph;
            Algorithms["SHAKE128WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
            Algorithms["SHAKE256WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_SHAKE256ph;

            Algorithms["SHA256WITHXMSS-SHA256"] = BCObjectIdentifiers.xmss_SHA256ph;
            Algorithms["SHA512WITHXMSS-SHA512"] = BCObjectIdentifiers.xmss_SHA512ph;
            Algorithms["SHAKE128WITHXMSS-SHAKE128"] = BCObjectIdentifiers.xmss_SHAKE128ph;
            Algorithms["SHAKE256WITHXMSS-SHAKE256"] = BCObjectIdentifiers.xmss_SHAKE256ph;

            Algorithms["SHA256WITHXMSSMT-SHA256"] = BCObjectIdentifiers.xmss_mt_SHA256ph;
            Algorithms["SHA512WITHXMSSMT-SHA512"] = BCObjectIdentifiers.xmss_mt_SHA512ph;
            Algorithms["SHAKE128WITHXMSSMT-SHAKE128"] = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
            Algorithms["SHAKE256WITHXMSSMT-SHAKE256"] = BCObjectIdentifiers.xmss_mt_SHAKE256ph;

            Algorithms["LMS"] = PkcsObjectIdentifiers.IdAlgHssLmsHashsig;

            Algorithms["XMSS"] = IsaraObjectIdentifiers.id_alg_xmss;
            Algorithms["XMSS-SHA256"] = BCObjectIdentifiers.xmss_SHA256;
            Algorithms["XMSS-SHA512"] = BCObjectIdentifiers.xmss_SHA512;
            Algorithms["XMSS-SHAKE128"] = BCObjectIdentifiers.xmss_SHAKE128;
            Algorithms["XMSS-SHAKE256"] = BCObjectIdentifiers.xmss_SHAKE256;

            Algorithms["XMSSMT"] = IsaraObjectIdentifiers.id_alg_xmssmt;
            Algorithms["XMSSMT-SHA256"] = BCObjectIdentifiers.xmss_mt_SHA256;
            Algorithms["XMSSMT-SHA512"] = BCObjectIdentifiers.xmss_mt_SHA512;
            Algorithms["XMSSMT-SHAKE128"] = BCObjectIdentifiers.xmss_mt_SHAKE128;
            Algorithms["XMSSMT-SHAKE256"] = BCObjectIdentifiers.xmss_mt_SHAKE256;

            Algorithms["SPHINCS+"] = BCObjectIdentifiers.sphincsPlus;
            Algorithms["SPHINCSPLUS"] = BCObjectIdentifiers.sphincsPlus;

            Algorithms["DILITHIUM2"] = BCObjectIdentifiers.dilithium2;
            Algorithms["DILITHIUM3"] = BCObjectIdentifiers.dilithium3;
            Algorithms["DILITHIUM5"] = BCObjectIdentifiers.dilithium5;
            Algorithms["DILITHIUM2-AES"] = BCObjectIdentifiers.dilithium2_aes;
            Algorithms["DILITHIUM3-AES"] = BCObjectIdentifiers.dilithium3_aes;
            Algorithms["DILITHIUM5-AES"] = BCObjectIdentifiers.dilithium5_aes;

            Algorithms["FALCON-512"] = BCObjectIdentifiers.falcon_512;
            Algorithms["FALCON-1024"] = BCObjectIdentifiers.falcon_1024;

            Algorithms["PICNIC"] = BCObjectIdentifiers.picnic_signature;
            Algorithms["SHA512WITHPICNIC"] = BCObjectIdentifiers.picnic_with_sha512;
            Algorithms["SHA3-512WITHPICNIC"] = BCObjectIdentifiers.picnic_with_sha3_512;
            Algorithms["SHAKE256WITHPICNIC"] = BCObjectIdentifiers.picnic_with_shake256;

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
            NoParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha224);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha256);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha384);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha512);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_224);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_256);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_384);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_512);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512);

            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA224);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA256);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA384);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA512);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_224);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_256);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_384);
            NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_512);

            //
            // RFC 4491
            //
            NoParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            NoParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            NoParams.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            NoParams.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            //
            // SPHINCS-256
            //
            NoParams.Add(BCObjectIdentifiers.sphincs256_with_SHA512);
            NoParams.Add(BCObjectIdentifiers.sphincs256_with_SHA3_512);

            //
            // SPHINCS-PLUS
            //
            NoParams.Add(BCObjectIdentifiers.sphincsPlus);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
            NoParams.Add(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);

            //
            // Dilithium
            //
            NoParams.Add(BCObjectIdentifiers.dilithium);
            NoParams.Add(BCObjectIdentifiers.dilithium2);
            NoParams.Add(BCObjectIdentifiers.dilithium3);
            NoParams.Add(BCObjectIdentifiers.dilithium5);
            NoParams.Add(BCObjectIdentifiers.dilithium2_aes);
            NoParams.Add(BCObjectIdentifiers.dilithium3_aes);
            NoParams.Add(BCObjectIdentifiers.dilithium5_aes);

            //
            // Falcon
            //
            NoParams.Add(BCObjectIdentifiers.falcon);
            NoParams.Add(BCObjectIdentifiers.falcon_512);
            NoParams.Add(BCObjectIdentifiers.falcon_1024);

            //
            // Picnic
            //
            NoParams.Add(BCObjectIdentifiers.picnic_signature);
            NoParams.Add(BCObjectIdentifiers.picnic_with_sha512);
            NoParams.Add(BCObjectIdentifiers.picnic_with_sha3_512);
            NoParams.Add(BCObjectIdentifiers.picnic_with_shake256);

            //
            // XMSS
            //
            NoParams.Add(BCObjectIdentifiers.xmss_SHA256ph);
            NoParams.Add(BCObjectIdentifiers.xmss_SHA512ph);
            NoParams.Add(BCObjectIdentifiers.xmss_SHAKE128ph);
            NoParams.Add(BCObjectIdentifiers.xmss_SHAKE256ph);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHA256ph);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHA512ph);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE128ph);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE256ph);

            NoParams.Add(BCObjectIdentifiers.xmss_SHA256);
            NoParams.Add(BCObjectIdentifiers.xmss_SHA512);
            NoParams.Add(BCObjectIdentifiers.xmss_SHAKE128);
            NoParams.Add(BCObjectIdentifiers.xmss_SHAKE256);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHA256);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHA512);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE128);
            NoParams.Add(BCObjectIdentifiers.xmss_mt_SHAKE256);

            NoParams.Add(IsaraObjectIdentifiers.id_alg_xmss);
            NoParams.Add(IsaraObjectIdentifiers.id_alg_xmssmt);

            //
            // qTESLA
            //
            NoParams.Add(BCObjectIdentifiers.qTESLA_p_I);
            NoParams.Add(BCObjectIdentifiers.qTESLA_p_III);

            //
            // SM2
            //
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_rmd160);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha1);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha224);
            NoParams.Add(GMObjectIdentifiers.sm2sign_with_sha256);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha384);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha512);
            NoParams.Add(GMObjectIdentifiers.sm2sign_with_sm3);

            // EdDSA
            NoParams.Add(EdECObjectIdentifiers.id_Ed25519);
            NoParams.Add(EdECObjectIdentifiers.id_Ed448);

            // RFC 8702
            NoParams.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            NoParams.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            NoParams.Add(CmsObjectIdentifiers.id_ecdsa_with_shake128);
            NoParams.Add(CmsObjectIdentifiers.id_ecdsa_with_shake256);

            //
            // PKCS 1.5 encrypted  algorithms
            //
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            Pkcs15RsaEncryption.Add(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            Pkcs15RsaEncryption.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            Pkcs15RsaEncryption.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            Pkcs15RsaEncryption.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
            Pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            Pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            Pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            Pkcs15RsaEncryption.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

            //
            // explicit params
            //
            AlgorithmIdentifier sha1AlgID = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            Parameters["SHA1WITHRSAANDMGF1"] = CreatePssParams(sha1AlgID, 20);

            AlgorithmIdentifier sha224AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            Parameters["SHA224WITHRSAANDMGF1"] = CreatePssParams(sha224AlgID, 28);

            AlgorithmIdentifier sha256AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            Parameters["SHA256WITHRSAANDMGF1"] = CreatePssParams(sha256AlgID, 32);

            AlgorithmIdentifier sha384AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            Parameters["SHA384WITHRSAANDMGF1"] = CreatePssParams(sha384AlgID, 48);

            AlgorithmIdentifier sha512AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            Parameters["SHA512WITHRSAANDMGF1"] = CreatePssParams(sha512AlgID, 64);

            AlgorithmIdentifier sha3_224AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_224, DerNull.Instance);
            Parameters["SHA3-224WITHRSAANDMGF1"] = CreatePssParams(sha3_224AlgID, 28);

            AlgorithmIdentifier sha3_256AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_256, DerNull.Instance);
            Parameters["SHA3-256WITHRSAANDMGF1"] = CreatePssParams(sha3_256AlgID, 32);

            AlgorithmIdentifier sha3_384AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_384, DerNull.Instance);
            Parameters["SHA3-384WITHRSAANDMGF1"] = CreatePssParams(sha3_384AlgID, 48);

            AlgorithmIdentifier sha3_512AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_512, DerNull.Instance);
            Parameters["SHA3-512WITHRSAANDMGF1"] = CreatePssParams(sha3_512AlgID, 64);

            //
            // digests
            //
            DigestOids[PkcsObjectIdentifiers.Sha224WithRsaEncryption] = NistObjectIdentifiers.IdSha224;
            DigestOids[PkcsObjectIdentifiers.Sha256WithRsaEncryption] = NistObjectIdentifiers.IdSha256;
            DigestOids[PkcsObjectIdentifiers.Sha384WithRsaEncryption] = NistObjectIdentifiers.IdSha384;
            DigestOids[PkcsObjectIdentifiers.Sha512WithRsaEncryption] = NistObjectIdentifiers.IdSha512;
            DigestOids[PkcsObjectIdentifiers.Sha512_224WithRSAEncryption] = NistObjectIdentifiers.IdSha512_224;
            DigestOids[PkcsObjectIdentifiers.Sha512_256WithRSAEncryption] = NistObjectIdentifiers.IdSha512_256;
            DigestOids[NistObjectIdentifiers.DsaWithSha224] = NistObjectIdentifiers.IdSha224;
            DigestOids[NistObjectIdentifiers.DsaWithSha256] = NistObjectIdentifiers.IdSha256;
            DigestOids[NistObjectIdentifiers.DsaWithSha384] = NistObjectIdentifiers.IdSha384;
            DigestOids[NistObjectIdentifiers.DsaWithSha512] = NistObjectIdentifiers.IdSha512;
            DigestOids[NistObjectIdentifiers.IdDsaWithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            DigestOids[NistObjectIdentifiers.IdDsaWithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            DigestOids[NistObjectIdentifiers.IdDsaWithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            DigestOids[NistObjectIdentifiers.IdDsaWithSha3_512] = NistObjectIdentifiers.IdSha3_512;
            DigestOids[NistObjectIdentifiers.IdEcdsaWithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            DigestOids[NistObjectIdentifiers.IdEcdsaWithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            DigestOids[NistObjectIdentifiers.IdEcdsaWithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            DigestOids[NistObjectIdentifiers.IdEcdsaWithSha3_512] = NistObjectIdentifiers.IdSha3_512;
            DigestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            DigestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            DigestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            DigestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512] = NistObjectIdentifiers.IdSha3_512;

            DigestOids[PkcsObjectIdentifiers.MD2WithRsaEncryption] = PkcsObjectIdentifiers.MD2;
            DigestOids[PkcsObjectIdentifiers.MD4WithRsaEncryption] = PkcsObjectIdentifiers.MD4;
            DigestOids[PkcsObjectIdentifiers.MD5WithRsaEncryption] = PkcsObjectIdentifiers.MD5;
            DigestOids[PkcsObjectIdentifiers.Sha1WithRsaEncryption] = OiwObjectIdentifiers.IdSha1;
            DigestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128] = TeleTrusTObjectIdentifiers.RipeMD128;
            DigestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160] = TeleTrusTObjectIdentifiers.RipeMD160;
            DigestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256] = TeleTrusTObjectIdentifiers.RipeMD256;
            DigestOids[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94] = CryptoProObjectIdentifiers.GostR3411;
            DigestOids[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001] = CryptoProObjectIdentifiers.GostR3411;
            DigestOids[RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
            DigestOids[RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;

            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_128s_r3] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_128f_r3] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_192s_r3] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_192f_r3] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_256s_r3] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_256f_r3] = NistObjectIdentifiers.IdShake256;

            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple] = NistObjectIdentifiers.IdSha256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple] = NistObjectIdentifiers.IdShake256;
            DigestOids[BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple] = NistObjectIdentifiers.IdShake256;

            //m_digestOids[GMObjectIdentifiers.sm2sign_with_rmd160] = TeleTrusTObjectIdentifiers.RipeMD160;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha1] = OiwObjectIdentifiers.IdSha1;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha224] = NistObjectIdentifiers.IdSha224;
            DigestOids[GMObjectIdentifiers.sm2sign_with_sha256] = NistObjectIdentifiers.IdSha256;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha384] = NistObjectIdentifiers.IdSha384;
            //m_digestOids[GMObjectIdentifiers.sm2sign_with_sha512] = NistObjectIdentifiers.IdSha512;
            DigestOids[GMObjectIdentifiers.sm2sign_with_sm3] = GMObjectIdentifiers.sm3;

            DigestOids[CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128] = NistObjectIdentifiers.IdShake128;
            DigestOids[CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256] = NistObjectIdentifiers.IdShake256;
            DigestOids[CmsObjectIdentifiers.id_ecdsa_with_shake128] = NistObjectIdentifiers.IdShake128;
            DigestOids[CmsObjectIdentifiers.id_ecdsa_with_shake256] = NistObjectIdentifiers.IdShake256;
        }

        private static RsassaPssParameters CreatePssParams(AlgorithmIdentifier hashAlgID, int saltSize)
        {
            return new RsassaPssParameters(
                hashAlgID,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgID),
                new DerInteger(saltSize),
                new DerInteger(1));
        }

        protected DefaultSignatureAlgorithmFinder()
        {
        }

        public virtual AlgorithmIdentifier Find(string signatureName)
        {
            if (!Algorithms.TryGetValue(signatureName, out var signatureOid))
                throw new ArgumentException("Unknown signature type requested: " + signatureName,
                    nameof(signatureName));

            AlgorithmIdentifier signatureAlgorithm;
            if (NoParams.Contains(signatureOid))
            {
                signatureAlgorithm = new AlgorithmIdentifier(signatureOid);
            }
            else if (Parameters.TryGetValue(signatureName, out var parameters))
            {
                signatureAlgorithm = new AlgorithmIdentifier(signatureOid, parameters);
            }
            else
            {
                signatureAlgorithm = new AlgorithmIdentifier(signatureOid, DerNull.Instance);
            }
            return signatureAlgorithm;
        }
    }
}
