using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Bsi;
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
using Org.BouncyCastle.Crypto.Parameters;

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

        private static void AddAlgorithm(string name, DerObjectIdentifier oid) => Algorithms.Add(name, oid);

        private static void AddAlgorithm(string name, DerObjectIdentifier oid, DerObjectIdentifier digestOid,
            bool isNoParams)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            AddAlgorithm(name, oid);

            if (digestOid != null)
            {
                AddDigestOid(oid, digestOid);
            }
            if (isNoParams)
            {
                NoParams.Add(oid);
            }
        }

        private static void AddDigestOid(DerObjectIdentifier signatureOid, DerObjectIdentifier digestOid) =>
            DigestOids.Add(signatureOid, digestOid);

        private static void AddParameters(string algorithmName, Asn1Encodable parameters)
        {
            if (parameters == null)
                throw new ArgumentException("use 'NoParams' instead for absent parameters", nameof(parameters));

            Parameters.Add(algorithmName, parameters);
        }

        private static RsassaPssParameters CreatePssParams(AlgorithmIdentifier hashAlgID, int saltSize)
        {
            return new RsassaPssParameters(
                hashAlgID,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgID),
                new DerInteger(saltSize),
                DerInteger.One);
        }

        static DefaultSignatureAlgorithmFinder()
        {
            AddAlgorithm("COMPOSITE", MiscObjectIdentifiers.id_alg_composite);

            AddAlgorithm("MD2WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD2WithRsaEncryption);
            AddAlgorithm("MD2WITHRSA", PkcsObjectIdentifiers.MD2WithRsaEncryption);
            AddAlgorithm("MD5WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD5WithRsaEncryption);
            AddAlgorithm("MD5WITHRSA", PkcsObjectIdentifiers.MD5WithRsaEncryption);
            AddAlgorithm("SHA1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            AddAlgorithm("SHA-1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            AddAlgorithm("SHA1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            AddAlgorithm("SHA-1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            AddAlgorithm("SHA224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            AddAlgorithm("SHA-224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            AddAlgorithm("SHA224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            AddAlgorithm("SHA-224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            AddAlgorithm("SHA256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            AddAlgorithm("SHA-256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            AddAlgorithm("SHA256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            AddAlgorithm("SHA-256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            AddAlgorithm("SHA384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            AddAlgorithm("SHA-384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            AddAlgorithm("SHA384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            AddAlgorithm("SHA-384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            AddAlgorithm("SHA512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            AddAlgorithm("SHA-512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            AddAlgorithm("SHA512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            AddAlgorithm("SHA-512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            AddAlgorithm("SHA512(224)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            AddAlgorithm("SHA-512(224)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            AddAlgorithm("SHA512(224)WITHRSA", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            AddAlgorithm("SHA-512(224)WITHRSA", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            AddAlgorithm("SHA512(256)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            AddAlgorithm("SHA-512(256)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            AddAlgorithm("SHA512(256)WITHRSA", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            AddAlgorithm("SHA-512(256)WITHRSA", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            AddAlgorithm("SHA1WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA3-224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA3-256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA3-384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("SHA3-512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            AddAlgorithm("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            AddAlgorithm("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            AddAlgorithm("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            AddAlgorithm("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            AddAlgorithm("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
            AddAlgorithm("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);

            AddAlgorithm("SHA1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
            AddAlgorithm("SHA-1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
            AddAlgorithm("DSAWITHSHA1", X9ObjectIdentifiers.IdDsaWithSha1);
            AddAlgorithm("SHA224WITHDSA", NistObjectIdentifiers.DsaWithSha224);
            AddAlgorithm("SHA256WITHDSA", NistObjectIdentifiers.DsaWithSha256);
            AddAlgorithm("SHA384WITHDSA", NistObjectIdentifiers.DsaWithSha384);
            AddAlgorithm("SHA512WITHDSA", NistObjectIdentifiers.DsaWithSha512);

            AddAlgorithm("SHA3-224WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_224);
            AddAlgorithm("SHA3-256WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_256);
            AddAlgorithm("SHA3-384WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_384);
            AddAlgorithm("SHA3-512WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_512);

            AddAlgorithm("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
            AddAlgorithm("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
            AddAlgorithm("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
            AddAlgorithm("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
            AddAlgorithm("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
            AddAlgorithm("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);

            AddAlgorithm("SHA3-224WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_224);
            AddAlgorithm("SHA3-256WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_256);
            AddAlgorithm("SHA3-384WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_384);
            AddAlgorithm("SHA3-512WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_512);

            AddAlgorithm("SHA3-224WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            AddAlgorithm("SHA3-256WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            AddAlgorithm("SHA3-384WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            AddAlgorithm("SHA3-512WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
            AddAlgorithm("SHA3-224WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            AddAlgorithm("SHA3-256WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            AddAlgorithm("SHA3-384WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            AddAlgorithm("SHA3-512WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
            AddAlgorithm("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            AddAlgorithm("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            AddAlgorithm("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            AddAlgorithm("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            AddAlgorithm("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            AddAlgorithm("GOST3411WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            AddAlgorithm("GOST3411WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
            AddAlgorithm("GOST3411WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            AddAlgorithm("GOST3411WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
            AddAlgorithm("GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            AddAlgorithm("GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
            AddAlgorithm("GOST3411-2012-256WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            AddAlgorithm("GOST3411-2012-512WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            // NOTE: Not in bc-java
            AddAlgorithm("GOST3411-2012-256WITHECGOST3410", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            AddAlgorithm("GOST3411-2012-512WITHECGOST3410", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            AddAlgorithm("SHA1WITHCVC-ECDSA", EacObjectIdentifiers.id_TA_ECDSA_SHA_1);
            AddAlgorithm("SHA224WITHCVC-ECDSA", EacObjectIdentifiers.id_TA_ECDSA_SHA_224);
            AddAlgorithm("SHA256WITHCVC-ECDSA", EacObjectIdentifiers.id_TA_ECDSA_SHA_256);
            AddAlgorithm("SHA384WITHCVC-ECDSA", EacObjectIdentifiers.id_TA_ECDSA_SHA_384);
            AddAlgorithm("SHA512WITHCVC-ECDSA", EacObjectIdentifiers.id_TA_ECDSA_SHA_512);
#pragma warning disable CS0618 // Type or member is obsolete
            AddAlgorithm("SHA3-512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA3_512);
            AddAlgorithm("SHA512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA512);
#pragma warning restore CS0618 // Type or member is obsolete

            AddAlgorithm("SHA1WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA1);
            AddAlgorithm("SHA224WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA224);
            AddAlgorithm("SHA256WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA256);
            AddAlgorithm("SHA384WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA384);
            AddAlgorithm("SHA512WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA512);
            AddAlgorithm("RIPEMD160WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_RIPEMD160);

            AddAlgorithm("SHA3-224WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA3_224);
            AddAlgorithm("SHA3-256WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA3_256);
            AddAlgorithm("SHA3-384WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA3_384);
            AddAlgorithm("SHA3-512WITHPLAIN-ECDSA", BsiObjectIdentifiers.ecdsa_plain_SHA3_512);

            // RFC 8692
            AddAlgorithm("SHAKE128WITHRSAPSS", X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            AddAlgorithm("SHAKE256WITHRSAPSS", X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            AddAlgorithm("SHAKE128WITHRSASSA-PSS", X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            AddAlgorithm("SHAKE256WITHRSASSA-PSS", X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            AddAlgorithm("SHAKE128WITHECDSA", X509ObjectIdentifiers.id_ecdsa_with_shake128);
            AddAlgorithm("SHAKE256WITHECDSA", X509ObjectIdentifiers.id_ecdsa_with_shake256);

            //AddAlgorithm("RIPEMD160WITHSM2", GMObjectIdentifiers.sm2sign_with_rmd160);
            //AddAlgorithm("SHA1WITHSM2", GMObjectIdentifiers.sm2sign_with_sha1);
            //AddAlgorithm("SHA224WITHSM2", GMObjectIdentifiers.sm2sign_with_sha224);
            AddAlgorithm("SHA256WITHSM2", GMObjectIdentifiers.sm2sign_with_sha256);
            //AddAlgorithm("SHA384WITHSM2", GMObjectIdentifiers.sm2sign_with_sha384);
            //AddAlgorithm("SHA512WITHSM2", GMObjectIdentifiers.sm2sign_with_sha512);
            AddAlgorithm("SM3WITHSM2", GMObjectIdentifiers.sm2sign_with_sm3);

            AddAlgorithm("SHA256WITHXMSS", BCObjectIdentifiers.xmss_SHA256ph);
            AddAlgorithm("SHA512WITHXMSS", BCObjectIdentifiers.xmss_SHA512ph);
            AddAlgorithm("SHAKE128WITHXMSS", BCObjectIdentifiers.xmss_SHAKE128ph);
            AddAlgorithm("SHAKE256WITHXMSS", BCObjectIdentifiers.xmss_SHAKE256ph);

            AddAlgorithm("SHA256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA256ph);
            AddAlgorithm("SHA512WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA512ph);
            AddAlgorithm("SHAKE128WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
            AddAlgorithm("SHAKE256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

            AddAlgorithm("SHA256WITHXMSS-SHA256", BCObjectIdentifiers.xmss_SHA256ph);
            AddAlgorithm("SHA512WITHXMSS-SHA512", BCObjectIdentifiers.xmss_SHA512ph);
            AddAlgorithm("SHAKE128WITHXMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128ph);
            AddAlgorithm("SHAKE256WITHXMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256ph);

            AddAlgorithm("SHA256WITHXMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256ph);
            AddAlgorithm("SHA512WITHXMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512ph);
            AddAlgorithm("SHAKE128WITHXMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
            AddAlgorithm("SHAKE256WITHXMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

            AddAlgorithm("LMS", PkcsObjectIdentifiers.IdAlgHssLmsHashsig);

            AddAlgorithm("XMSS", IsaraObjectIdentifiers.id_alg_xmss);
            AddAlgorithm("XMSS-SHA256", BCObjectIdentifiers.xmss_SHA256);
            AddAlgorithm("XMSS-SHA512", BCObjectIdentifiers.xmss_SHA512);
            AddAlgorithm("XMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128);
            AddAlgorithm("XMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256);

            AddAlgorithm("XMSSMT", IsaraObjectIdentifiers.id_alg_xmssmt);
            AddAlgorithm("XMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256);
            AddAlgorithm("XMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512);
            AddAlgorithm("XMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128);
            AddAlgorithm("XMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256);

#pragma warning disable CS0618 // Type or member is obsolete
            AddAlgorithm("SPHINCS+", BCObjectIdentifiers.sphincsPlus);
            AddAlgorithm("SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus);

            AddAlgorithm("DILITHIUM2", BCObjectIdentifiers.dilithium2);
            AddAlgorithm("DILITHIUM3", BCObjectIdentifiers.dilithium3);
            AddAlgorithm("DILITHIUM5", BCObjectIdentifiers.dilithium5);
            AddAlgorithm("DILITHIUM2-AES", BCObjectIdentifiers.dilithium2_aes);
            AddAlgorithm("DILITHIUM3-AES", BCObjectIdentifiers.dilithium3_aes);
            AddAlgorithm("DILITHIUM5-AES", BCObjectIdentifiers.dilithium5_aes);
#pragma warning restore CS0618 // Type or member is obsolete

            AddAlgorithm("FALCON-512", BCObjectIdentifiers.falcon_512);
            AddAlgorithm("FALCON-1024", BCObjectIdentifiers.falcon_1024);

            AddAlgorithm("PICNIC", BCObjectIdentifiers.picnic_signature);
            AddAlgorithm("SHA512WITHPICNIC", BCObjectIdentifiers.picnic_with_sha512);
            AddAlgorithm("SHA3-512WITHPICNIC", BCObjectIdentifiers.picnic_with_sha3_512);
            AddAlgorithm("SHAKE256WITHPICNIC", BCObjectIdentifiers.picnic_with_shake256);

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //

            NoParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha224);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha256);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha384);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha512);

            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_224);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_256);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_384);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_512);

            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            NoParams.Add(OiwObjectIdentifiers.DsaWithSha1);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);

            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512);

            //NoParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA1);
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

#pragma warning disable CS0618 // Type or member is obsolete
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
#pragma warning restore CS0618 // Type or member is obsolete

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
            //NoParams.Add(GMObjectIdentifiers.sm2sign_with_rmd160);
            //NoParams.Add(GMObjectIdentifiers.sm2sign_with_sha1);
            //NoParams.Add(GMObjectIdentifiers.sm2sign_with_sha224);
            NoParams.Add(GMObjectIdentifiers.sm2sign_with_sha256);
            //NoParams.Add(GMObjectIdentifiers.sm2sign_with_sha384);
            //NoParams.Add(GMObjectIdentifiers.sm2sign_with_sha512);
            NoParams.Add(GMObjectIdentifiers.sm2sign_with_sm3);

            // RFC 8692
            NoParams.Add(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            NoParams.Add(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            NoParams.Add(X509ObjectIdentifiers.id_ecdsa_with_shake128);
            NoParams.Add(X509ObjectIdentifiers.id_ecdsa_with_shake256);

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
            AddParameters("SHA1WITHRSAANDMGF1", CreatePssParams(sha1AlgID, 20));

            AlgorithmIdentifier sha224AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            AddParameters("SHA224WITHRSAANDMGF1", CreatePssParams(sha224AlgID, 28));

            AlgorithmIdentifier sha256AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            AddParameters("SHA256WITHRSAANDMGF1", CreatePssParams(sha256AlgID, 32));

            AlgorithmIdentifier sha384AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            AddParameters("SHA384WITHRSAANDMGF1", CreatePssParams(sha384AlgID, 48));

            AlgorithmIdentifier sha512AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            AddParameters("SHA512WITHRSAANDMGF1", CreatePssParams(sha512AlgID, 64));

            AlgorithmIdentifier sha3_224AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_224, DerNull.Instance);
            AddParameters("SHA3-224WITHRSAANDMGF1", CreatePssParams(sha3_224AlgID, 28));

            AlgorithmIdentifier sha3_256AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_256, DerNull.Instance);
            AddParameters("SHA3-256WITHRSAANDMGF1", CreatePssParams(sha3_256AlgID, 32));

            AlgorithmIdentifier sha3_384AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_384, DerNull.Instance);
            AddParameters("SHA3-384WITHRSAANDMGF1", CreatePssParams(sha3_384AlgID, 48));

            AlgorithmIdentifier sha3_512AlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_512, DerNull.Instance);
            AddParameters("SHA3-512WITHRSAANDMGF1", CreatePssParams(sha3_512AlgID, 64));

            //
            // digests
            //
            AddDigestOid(PkcsObjectIdentifiers.Sha224WithRsaEncryption, NistObjectIdentifiers.IdSha224);
            AddDigestOid(PkcsObjectIdentifiers.Sha256WithRsaEncryption, NistObjectIdentifiers.IdSha256);
            AddDigestOid(PkcsObjectIdentifiers.Sha384WithRsaEncryption, NistObjectIdentifiers.IdSha384);
            AddDigestOid(PkcsObjectIdentifiers.Sha512WithRsaEncryption, NistObjectIdentifiers.IdSha512);
            AddDigestOid(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption, NistObjectIdentifiers.IdSha512_224);
            AddDigestOid(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption, NistObjectIdentifiers.IdSha512_256);
            AddDigestOid(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, NistObjectIdentifiers.IdSha3_224);
            AddDigestOid(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, NistObjectIdentifiers.IdSha3_256);
            AddDigestOid(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, NistObjectIdentifiers.IdSha3_384);
            AddDigestOid(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, NistObjectIdentifiers.IdSha3_512);

            AddDigestOid(PkcsObjectIdentifiers.MD2WithRsaEncryption, PkcsObjectIdentifiers.MD2);
            AddDigestOid(PkcsObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            AddDigestOid(PkcsObjectIdentifiers.MD5WithRsaEncryption, PkcsObjectIdentifiers.MD5);
            AddDigestOid(PkcsObjectIdentifiers.Sha1WithRsaEncryption, OiwObjectIdentifiers.IdSha1);
            AddDigestOid(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, TeleTrusTObjectIdentifiers.RipeMD128);
            AddDigestOid(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, TeleTrusTObjectIdentifiers.RipeMD160);
            AddDigestOid(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, TeleTrusTObjectIdentifiers.RipeMD256);
            AddDigestOid(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, CryptoProObjectIdentifiers.GostR3411);
            AddDigestOid(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, CryptoProObjectIdentifiers.GostR3411);
            AddDigestOid(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            AddDigestOid(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

            AddDigestOid(X9ObjectIdentifiers.IdDsaWithSha1, OiwObjectIdentifiers.IdSha1);
            AddDigestOid(OiwObjectIdentifiers.DsaWithSha1, OiwObjectIdentifiers.IdSha1);
            AddDigestOid(NistObjectIdentifiers.DsaWithSha224, NistObjectIdentifiers.IdSha224);
            AddDigestOid(NistObjectIdentifiers.DsaWithSha256, NistObjectIdentifiers.IdSha256);
            AddDigestOid(NistObjectIdentifiers.DsaWithSha384, NistObjectIdentifiers.IdSha384);
            AddDigestOid(NistObjectIdentifiers.DsaWithSha512, NistObjectIdentifiers.IdSha512);

            AddDigestOid(NistObjectIdentifiers.IdDsaWithSha3_224, NistObjectIdentifiers.IdSha3_224);
            AddDigestOid(NistObjectIdentifiers.IdDsaWithSha3_256, NistObjectIdentifiers.IdSha3_256);
            AddDigestOid(NistObjectIdentifiers.IdDsaWithSha3_384, NistObjectIdentifiers.IdSha3_384);
            AddDigestOid(NistObjectIdentifiers.IdDsaWithSha3_512, NistObjectIdentifiers.IdSha3_512);

            AddDigestOid(X9ObjectIdentifiers.ECDsaWithSha1, OiwObjectIdentifiers.IdSha1);
            AddDigestOid(X9ObjectIdentifiers.ECDsaWithSha224, NistObjectIdentifiers.IdSha224);
            AddDigestOid(X9ObjectIdentifiers.ECDsaWithSha256, NistObjectIdentifiers.IdSha256);
            AddDigestOid(X9ObjectIdentifiers.ECDsaWithSha384, NistObjectIdentifiers.IdSha384);
            AddDigestOid(X9ObjectIdentifiers.ECDsaWithSha512, NistObjectIdentifiers.IdSha512);

            AddDigestOid(NistObjectIdentifiers.IdEcdsaWithSha3_224, NistObjectIdentifiers.IdSha3_224);
            AddDigestOid(NistObjectIdentifiers.IdEcdsaWithSha3_256, NistObjectIdentifiers.IdSha3_256);
            AddDigestOid(NistObjectIdentifiers.IdEcdsaWithSha3_384, NistObjectIdentifiers.IdSha3_384);
            AddDigestOid(NistObjectIdentifiers.IdEcdsaWithSha3_512, NistObjectIdentifiers.IdSha3_512);

#pragma warning disable CS0618 // Type or member is obsolete
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, NistObjectIdentifiers.IdShake256);

            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, NistObjectIdentifiers.IdSha256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, NistObjectIdentifiers.IdShake256);
            AddDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, NistObjectIdentifiers.IdShake256);
#pragma warning restore CS0618 // Type or member is obsolete

            //AddDigestOid(GMObjectIdentifiers.sm2sign_with_rmd160, TeleTrusTObjectIdentifiers.RipeMD160);
            //AddDigestOid(GMObjectIdentifiers.sm2sign_with_sha1, OiwObjectIdentifiers.IdSha1);
            //AddDigestOid(GMObjectIdentifiers.sm2sign_with_sha224, NistObjectIdentifiers.IdSha224);
            AddDigestOid(GMObjectIdentifiers.sm2sign_with_sha256, NistObjectIdentifiers.IdSha256);
            //AddDigestOid(GMObjectIdentifiers.sm2sign_with_sha384, NistObjectIdentifiers.IdSha384);
            //AddDigestOid(GMObjectIdentifiers.sm2sign_with_sha512, NistObjectIdentifiers.IdSha512);
            AddDigestOid(GMObjectIdentifiers.sm2sign_with_sm3, GMObjectIdentifiers.sm3);

            AddDigestOid(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128, NistObjectIdentifiers.IdShake128);
            AddDigestOid(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256, NistObjectIdentifiers.IdShake256);
            AddDigestOid(X509ObjectIdentifiers.id_ecdsa_with_shake128, NistObjectIdentifiers.IdShake128);
            AddDigestOid(X509ObjectIdentifiers.id_ecdsa_with_shake256, NistObjectIdentifiers.IdShake256);

            /*
             * EdDSA
             */
            AddAlgorithm("Ed25519", EdECObjectIdentifiers.id_Ed25519, digestOid: null, isNoParams: true);
            AddAlgorithm("Ed448", EdECObjectIdentifiers.id_Ed448, digestOid: null, isNoParams: true);

            /*
             * ML-DSA
             */
            foreach (MLDsaParameters mlDsa in MLDsaParameters.ByName.Values)
            {
                AddAlgorithm(mlDsa.Name, mlDsa.Oid, mlDsa.PreHashOid, isNoParams: true);
            }

            /*
             * SLH-DSA
             */
            foreach (SlhDsaParameters slhDsa in SlhDsaParameters.ByName.Values)
            {
                AddAlgorithm(slhDsa.Name, slhDsa.Oid, slhDsa.PreHashOid, isNoParams: true);
            }
        }

        protected DefaultSignatureAlgorithmFinder()
        {
        }

        public virtual AlgorithmIdentifier Find(string signatureName)
        {
            if (!Algorithms.TryGetValue(signatureName, out var sigAlgOid))
                throw new ArgumentException($"Unknown signature name: {signatureName}", nameof(signatureName));

            if (NoParams.Contains(sigAlgOid))
                return new AlgorithmIdentifier(sigAlgOid);

            if (!Parameters.TryGetValue(signatureName, out var sigAlgParams))
            {
                sigAlgParams = DerNull.Instance;
            }

            return new AlgorithmIdentifier(sigAlgOid, sigAlgParams);
        }
    }
}
