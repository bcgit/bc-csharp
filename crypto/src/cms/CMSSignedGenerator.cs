using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    public class DefaultSignatureAlgorithmIdentifierFinder
    {
        private static readonly IDictionary algorithms = Platform.CreateHashtable();
        private static readonly ISet noParams = new HashSet();
        private static readonly IDictionary _params = Platform.CreateHashtable();
        private static readonly ISet pkcs15RsaEncryption = new HashSet();
        private static readonly IDictionary digestOids = Platform.CreateHashtable();

        private static readonly IDictionary digestBuilders = Platform.CreateHashtable();

        private static readonly DerObjectIdentifier ENCRYPTION_RSA = PkcsObjectIdentifiers.RsaEncryption;
        private static readonly DerObjectIdentifier ENCRYPTION_DSA = X9ObjectIdentifiers.IdDsaWithSha1;
        private static readonly DerObjectIdentifier ENCRYPTION_ECDSA = X9ObjectIdentifiers.ECDsaWithSha1;
        private static readonly DerObjectIdentifier ENCRYPTION_RSA_PSS = PkcsObjectIdentifiers.IdRsassaPss;
        private static readonly DerObjectIdentifier ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.GostR3410x94;
        private static readonly DerObjectIdentifier ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.GostR3410x2001;
        private static readonly DerObjectIdentifier ENCRYPTION_ECGOST3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
        private static readonly DerObjectIdentifier ENCRYPTION_ECGOST3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;

        static DefaultSignatureAlgorithmIdentifierFinder()
        {
            algorithms["MD2WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            algorithms["MD2WITHRSA"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            algorithms["MD5WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;
            algorithms["MD5WITHRSA"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;
            algorithms["SHA1WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            algorithms["SHA1WITHRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            algorithms["SHA-1WITHRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            algorithms["SHA224WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            algorithms["SHA224WITHRSA"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            algorithms["SHA256WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            algorithms["SHA256WITHRSA"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            algorithms["SHA384WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            algorithms["SHA384WITHRSA"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            algorithms["SHA512WITHRSAENCRYPTION"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            algorithms["SHA512WITHRSA"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            algorithms["SHA1WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA224WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA256WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA384WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA512WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA3-224WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA3-256WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA3-384WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["SHA3-512WITHRSAANDMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            algorithms["RIPEMD160WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
            algorithms["RIPEMD160WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
            algorithms["RIPEMD128WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            algorithms["RIPEMD128WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            algorithms["RIPEMD256WITHRSAENCRYPTION"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
            algorithms["RIPEMD256WITHRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
            algorithms["SHA1WITHDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;
            algorithms["SHA-1WITHDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;
            algorithms["DSAWITHSHA1"] = X9ObjectIdentifiers.IdDsaWithSha1;
            algorithms["SHA224WITHDSA"] = NistObjectIdentifiers.DsaWithSha224;
            algorithms["SHA256WITHDSA"] = NistObjectIdentifiers.DsaWithSha256;
            algorithms["SHA384WITHDSA"] = NistObjectIdentifiers.DsaWithSha384;
            algorithms["SHA512WITHDSA"] = NistObjectIdentifiers.DsaWithSha512;
            algorithms["SHA3-224WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_224; //  id_dsa_with_sha3_224;
            algorithms["SHA3-256WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_256; //id_dsa_with_sha3_256;
            algorithms["SHA3-384WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_384; //id_dsa_with_sha3_384;
            algorithms["SHA3-512WITHDSA"] = NistObjectIdentifiers.IdDsaWithSha3_512; //id_dsa_with_sha3_512;
            algorithms["SHA3-224WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_224;//   id_ecdsa_with_sha3_224;
            algorithms["SHA3-256WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_256;//id_ecdsa_with_sha3_256;
            algorithms["SHA3-384WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_384;//id_ecdsa_with_sha3_384;
            algorithms["SHA3-512WITHECDSA"] = NistObjectIdentifiers.IdEcdsaWithSha3_512;//id_ecdsa_with_sha3_512;
            algorithms["SHA3-224WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;//   id_rsassa_pkcs1_v1_5_with_sha3_224;
            algorithms["SHA3-256WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;// id_rsassa_pkcs1_v1_5_with_sha3_256;
            algorithms["SHA3-384WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;// id_rsassa_pkcs1_v1_5_with_sha3_384;
            algorithms["SHA3-512WITHRSA"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;// id_rsassa_pkcs1_v1_5_with_sha3_512;
            algorithms["SHA3-224WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;// id_rsassa_pkcs1_v1_5_with_sha3_224;
            algorithms["SHA3-256WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;// id_rsassa_pkcs1_v1_5_with_sha3_256;
            algorithms["SHA3-384WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384; //id_rsassa_pkcs1_v1_5_with_sha3_384;
            algorithms["SHA3-512WITHRSAENCRYPTION"] = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512; // id_rsassa_pkcs1_v1_5_with_sha3_512;
            algorithms["SHA1WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha1;
            algorithms["ECDSAWITHSHA1"] = X9ObjectIdentifiers.ECDsaWithSha1;
            algorithms["SHA224WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha224;
            algorithms["SHA256WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha224;
            algorithms["SHA384WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha384;
            algorithms["SHA512WITHECDSA"] = X9ObjectIdentifiers.ECDsaWithSha256;


            algorithms["GOST3411WITHGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            algorithms["GOST3411WITHGOST3410-94"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            algorithms["GOST3411WITHECGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            algorithms["GOST3411WITHECGOST3410-2001"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            algorithms["GOST3411WITHGOST3410-2001"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
            algorithms["GOST3411WITHECGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            algorithms["GOST3411WITHECGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            algorithms["GOST3411WITHGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            algorithms["GOST3411WITHGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            algorithms["GOST3411-2012-256WITHECGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            algorithms["GOST3411-2012-512WITHECGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            algorithms["GOST3411-2012-256WITHGOST3410-2012-256"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256;
            algorithms["GOST3411-2012-512WITHGOST3410-2012-512"] = RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512;
            algorithms["SHA1WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA1;
            algorithms["SHA224WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA224;
            algorithms["SHA256WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA256;
            algorithms["SHA384WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA384;
            algorithms["SHA512WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_SHA512;
            algorithms["RIPEMD160WITHPLAIN-ECDSA"] = BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;
            algorithms["SHA1WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_1;
            algorithms["SHA224WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_224;
            algorithms["SHA256WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_256;
            algorithms["SHA384WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_384;
            algorithms["SHA512WITHCVC-ECDSA"] = EacObjectIdentifiers.id_TA_ECDSA_SHA_512;
            algorithms["SHA3-512WITHSPHINCS256"] = BCObjectIdentifiers.sphincs256_with_SHA3_512;
            algorithms["SHA512WITHSPHINCS256"] = BCObjectIdentifiers.sphincs256_with_SHA512;

            algorithms["SHA256WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sha256;
            algorithms["SM3WITHSM2"] = GMObjectIdentifiers.sm2sign_with_sm3;

            algorithms["SHA256WITHXMSS"] = BCObjectIdentifiers.xmss_with_SHA256;
            algorithms["SHA512WITHXMSS"] = BCObjectIdentifiers.xmss_with_SHA512;
            algorithms["SHAKE128WITHXMSS"] = BCObjectIdentifiers.xmss_with_SHAKE128;
            algorithms["SHAKE256WITHXMSS"] = BCObjectIdentifiers.xmss_with_SHAKE256;

            algorithms["SHA256WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_with_SHA256;
            algorithms["SHA512WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_with_SHA512;
            algorithms["SHAKE128WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_with_SHAKE128;
            algorithms["SHAKE256WITHXMSSMT"] = BCObjectIdentifiers.xmss_mt_with_SHAKE256;


            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            noParams.Add((object)X9ObjectIdentifiers.ECDsaWithSha1);
            noParams.Add((object)X9ObjectIdentifiers.ECDsaWithSha224);
            noParams.Add((object)X9ObjectIdentifiers.ECDsaWithSha256);
            noParams.Add((object)X9ObjectIdentifiers.ECDsaWithSha384);
            noParams.Add((object)X9ObjectIdentifiers.ECDsaWithSha512);
            noParams.Add((object)X9ObjectIdentifiers.IdDsaWithSha1);
            noParams.Add((object)NistObjectIdentifiers.DsaWithSha224);
            noParams.Add((object)NistObjectIdentifiers.DsaWithSha256);
            noParams.Add((object)NistObjectIdentifiers.DsaWithSha384);
            noParams.Add((object)NistObjectIdentifiers.DsaWithSha512);
            noParams.Add((object)NistObjectIdentifiers.IdDsaWithSha3_224);
            noParams.Add((object)NistObjectIdentifiers.IdDsaWithSha3_256);
            noParams.Add((object)NistObjectIdentifiers.IdDsaWithSha3_384);
            noParams.Add((object)NistObjectIdentifiers.IdDsaWithSha3_512);
            noParams.Add((object)NistObjectIdentifiers.IdEcdsaWithSha3_224);
            noParams.Add((object)NistObjectIdentifiers.IdEcdsaWithSha3_256);
            noParams.Add((object)NistObjectIdentifiers.IdEcdsaWithSha3_384);
            noParams.Add((object)NistObjectIdentifiers.IdEcdsaWithSha3_512);


            //
            // RFC 4491
            //
            noParams.Add((object)CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            noParams.Add((object)CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            noParams.Add((object)RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            noParams.Add((object)RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            //
            // SPHINCS-256
            //
            noParams.Add((object)BCObjectIdentifiers.sphincs256_with_SHA512);
            noParams.Add((object)BCObjectIdentifiers.sphincs256_with_SHA3_512);

            //
            // XMSS
            //
            noParams.Add((object)BCObjectIdentifiers.xmss_with_SHA256);
            noParams.Add((object)BCObjectIdentifiers.xmss_with_SHA512);
            noParams.Add((object)BCObjectIdentifiers.xmss_with_SHAKE128);
            noParams.Add((object)BCObjectIdentifiers.xmss_with_SHAKE256);
            noParams.Add((object)BCObjectIdentifiers.xmss_mt_with_SHA256);
            noParams.Add((object)BCObjectIdentifiers.xmss_mt_with_SHA512);
            noParams.Add((object)BCObjectIdentifiers.xmss_mt_with_SHAKE128);
            noParams.Add((object)BCObjectIdentifiers.xmss_mt_with_SHAKE256);

            //
            // SM2
            //
            noParams.Add((object)GMObjectIdentifiers.sm2sign_with_sha256);
            noParams.Add((object)GMObjectIdentifiers.sm2sign_with_sm3);

            //
            // PKCS 1.5 encrypted  algorithms
            //
            pkcs15RsaEncryption.Add((object)PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            pkcs15RsaEncryption.Add((object)PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            pkcs15RsaEncryption.Add((object)PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            pkcs15RsaEncryption.Add((object)PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            pkcs15RsaEncryption.Add((object)PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            pkcs15RsaEncryption.Add((object)TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            pkcs15RsaEncryption.Add((object)TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            pkcs15RsaEncryption.Add((object)TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
            pkcs15RsaEncryption.Add((object)NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            pkcs15RsaEncryption.Add((object)NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            pkcs15RsaEncryption.Add((object)NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            pkcs15RsaEncryption.Add((object)NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

            //
            // explicit params
            //
            AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            _params["SHA1WITHRSAANDMGF1"] = CreatePssParams(sha1AlgId, 20);

            AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            _params["SHA224WITHRSAANDMGF1"] = CreatePssParams(sha224AlgId, 28);

            AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            _params["SHA256WITHRSAANDMGF1"] = CreatePssParams(sha256AlgId, 32);

            AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            _params["SHA384WITHRSAANDMGF1"] = CreatePssParams(sha384AlgId, 48);

            AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            _params["SHA512WITHRSAANDMGF1"] = CreatePssParams(sha512AlgId, 64);

            AlgorithmIdentifier sha3_224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_224, DerNull.Instance);
            _params["SHA3-224WITHRSAANDMGF1"] = CreatePssParams(sha3_224AlgId, 28);

            AlgorithmIdentifier sha3_256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_256, DerNull.Instance);
            _params["SHA3-256WITHRSAANDMGF1"] = CreatePssParams(sha3_256AlgId, 32);

            AlgorithmIdentifier sha3_384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_384, DerNull.Instance);
            _params["SHA3-384WITHRSAANDMGF1"] = CreatePssParams(sha3_384AlgId, 48);

            AlgorithmIdentifier sha3_512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_512, DerNull.Instance);
            _params["SHA3-512WITHRSAANDMGF1"] = CreatePssParams(sha3_512AlgId, 64);

            //
            // digests
            //
            digestOids[PkcsObjectIdentifiers.Sha224WithRsaEncryption] = NistObjectIdentifiers.IdSha224;
            digestOids[PkcsObjectIdentifiers.Sha256WithRsaEncryption] = NistObjectIdentifiers.IdSha256;
            digestOids[PkcsObjectIdentifiers.Sha384WithRsaEncryption] = NistObjectIdentifiers.IdSha384;
            digestOids[PkcsObjectIdentifiers.Sha512WithRsaEncryption] = NistObjectIdentifiers.IdSha512;
            digestOids[NistObjectIdentifiers.DsaWithSha224] = NistObjectIdentifiers.IdSha224;
            digestOids[NistObjectIdentifiers.DsaWithSha224] = NistObjectIdentifiers.IdSha256;
            digestOids[NistObjectIdentifiers.DsaWithSha224] = NistObjectIdentifiers.IdSha384;
            digestOids[NistObjectIdentifiers.DsaWithSha224] = NistObjectIdentifiers.IdSha512;
            digestOids[NistObjectIdentifiers.IdDsaWithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            digestOids[NistObjectIdentifiers.IdDsaWithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            digestOids[NistObjectIdentifiers.IdDsaWithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            digestOids[NistObjectIdentifiers.IdDsaWithSha3_512] = NistObjectIdentifiers.IdSha3_512;
            digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            digestOids[NistObjectIdentifiers.IdEcdsaWithSha3_512] = NistObjectIdentifiers.IdSha3_512;
            digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224] = NistObjectIdentifiers.IdSha3_224;
            digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256] = NistObjectIdentifiers.IdSha3_256;
            digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384] = NistObjectIdentifiers.IdSha3_384;
            digestOids[NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512] = NistObjectIdentifiers.IdSha3_512;

            digestOids[PkcsObjectIdentifiers.MD2WithRsaEncryption] = PkcsObjectIdentifiers.MD2;
            digestOids[PkcsObjectIdentifiers.MD4WithRsaEncryption] = PkcsObjectIdentifiers.MD4;
            digestOids[PkcsObjectIdentifiers.MD5WithRsaEncryption] = PkcsObjectIdentifiers.MD5;
            digestOids[PkcsObjectIdentifiers.Sha1WithRsaEncryption] = OiwObjectIdentifiers.IdSha1;
            digestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128] = TeleTrusTObjectIdentifiers.RipeMD128;
            digestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160] = TeleTrusTObjectIdentifiers.RipeMD160;
            digestOids[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256] = TeleTrusTObjectIdentifiers.RipeMD256;
            digestOids[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94] = CryptoProObjectIdentifiers.GostR3411;
            digestOids[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001] = CryptoProObjectIdentifiers.GostR3411;
            digestOids[RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
            digestOids[RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;

            digestOids[GMObjectIdentifiers.sm2sign_with_sha256] = NistObjectIdentifiers.IdSha256;
            digestOids[GMObjectIdentifiers.sm2sign_with_sm3] = GMObjectIdentifiers.sm3;
        }

        private static AlgorithmIdentifier Generate(string signatureAlgorithm)
        {
            AlgorithmIdentifier sigAlgId;
            AlgorithmIdentifier encAlgId;
            AlgorithmIdentifier digAlgId;

            string algorithmName = Strings.ToUpperCase(signatureAlgorithm);
            DerObjectIdentifier sigOID = (DerObjectIdentifier)algorithms[algorithmName];
            if (sigOID == null)
            {
                throw new ArgumentException("Unknown signature type requested: " + algorithmName);
            }

            if (noParams.Contains(sigOID))
            {
                sigAlgId = new AlgorithmIdentifier(sigOID);
            }
            else if (_params.Contains(algorithmName))
            {
                sigAlgId = new AlgorithmIdentifier(sigOID, (Asn1Encodable)_params[algorithmName]);
            }
            else
            {
                sigAlgId = new AlgorithmIdentifier(sigOID, DerNull.Instance);
            }

            if (pkcs15RsaEncryption.Contains(sigOID))
            {
                encAlgId = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            }
            else
            {
                encAlgId = sigAlgId;
            }

            if (sigAlgId.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
            {
                digAlgId = ((RsassaPssParameters)sigAlgId.Parameters).HashAlgorithm;
            }
            else
            {
                digAlgId = new AlgorithmIdentifier((DerObjectIdentifier)digestOids[sigOID], DerNull.Instance);
            }

            return sigAlgId;
        }

        private static RsassaPssParameters CreatePssParams(AlgorithmIdentifier hashAlgId, int saltSize)
        {
            return new RsassaPssParameters(
                hashAlgId,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgId),
                new DerInteger(saltSize),
                new DerInteger(1));
        }

        public AlgorithmIdentifier Find(string sigAlgName)
        {
            return Generate(sigAlgName);
        }
    }

    public class DefaultDigestAlgorithmIdentifierFinder
    {
        private static readonly IDictionary digestOids = Platform.CreateHashtable();
        private static readonly IDictionary digestNameToOids = Platform.CreateHashtable();

        static DefaultDigestAlgorithmIdentifierFinder()
        {
            //
            // digests
            //
            digestOids.Add(OiwObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            digestOids.Add(OiwObjectIdentifiers.MD4WithRsa, PkcsObjectIdentifiers.MD4);
            digestOids.Add(OiwObjectIdentifiers.MD5WithRsa, PkcsObjectIdentifiers.MD5);
            digestOids.Add(OiwObjectIdentifiers.Sha1WithRsa, OiwObjectIdentifiers.IdSha1);
            digestOids.Add(OiwObjectIdentifiers.DsaWithSha1, OiwObjectIdentifiers.IdSha1);

            digestOids.Add(PkcsObjectIdentifiers.Sha224WithRsaEncryption, NistObjectIdentifiers.IdSha224);
            digestOids.Add(PkcsObjectIdentifiers.Sha256WithRsaEncryption, NistObjectIdentifiers.IdSha256);
            digestOids.Add(PkcsObjectIdentifiers.Sha384WithRsaEncryption, NistObjectIdentifiers.IdSha384);
            digestOids.Add(PkcsObjectIdentifiers.Sha512WithRsaEncryption, NistObjectIdentifiers.IdSha512);
            digestOids.Add(PkcsObjectIdentifiers.MD2WithRsaEncryption, PkcsObjectIdentifiers.MD2);
            digestOids.Add(PkcsObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            digestOids.Add(PkcsObjectIdentifiers.MD5WithRsaEncryption, PkcsObjectIdentifiers.MD5);
            digestOids.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption, OiwObjectIdentifiers.IdSha1);

            digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha1, OiwObjectIdentifiers.IdSha1);
            digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha224, NistObjectIdentifiers.IdSha224);
            digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha256, NistObjectIdentifiers.IdSha256);
            digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha384, NistObjectIdentifiers.IdSha384);
            digestOids.Add(X9ObjectIdentifiers.ECDsaWithSha512, NistObjectIdentifiers.IdSha512);
            digestOids.Add(X9ObjectIdentifiers.IdDsaWithSha1, OiwObjectIdentifiers.IdSha1);

            digestOids.Add(NistObjectIdentifiers.DsaWithSha224, NistObjectIdentifiers.IdSha224);
            digestOids.Add(NistObjectIdentifiers.DsaWithSha256, NistObjectIdentifiers.IdSha256);
            digestOids.Add(NistObjectIdentifiers.DsaWithSha384, NistObjectIdentifiers.IdSha384);
            digestOids.Add(NistObjectIdentifiers.DsaWithSha512, NistObjectIdentifiers.IdSha512);

            digestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, TeleTrusTObjectIdentifiers.RipeMD128);
            digestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, TeleTrusTObjectIdentifiers.RipeMD160);
            digestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, TeleTrusTObjectIdentifiers.RipeMD256);

            digestOids.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, CryptoProObjectIdentifiers.GostR3411);
            digestOids.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, CryptoProObjectIdentifiers.GostR3411);

            digestNameToOids.Add("SHA-1", OiwObjectIdentifiers.IdSha1);
            digestNameToOids.Add("SHA-224", NistObjectIdentifiers.IdSha224);
            digestNameToOids.Add("SHA-256", NistObjectIdentifiers.IdSha256);
            digestNameToOids.Add("SHA-384", NistObjectIdentifiers.IdSha384);
            digestNameToOids.Add("SHA-512", NistObjectIdentifiers.IdSha512);

            digestNameToOids.Add("SHA1", OiwObjectIdentifiers.IdSha1);
            digestNameToOids.Add("SHA224", NistObjectIdentifiers.IdSha224);
            digestNameToOids.Add("SHA256", NistObjectIdentifiers.IdSha256);
            digestNameToOids.Add("SHA384", NistObjectIdentifiers.IdSha384);
            digestNameToOids.Add("SHA512", NistObjectIdentifiers.IdSha512);

            digestNameToOids.Add("SHA3-224", NistObjectIdentifiers.IdSha3_224);
            digestNameToOids.Add("SHA3-256", NistObjectIdentifiers.IdSha3_256);
            digestNameToOids.Add("SHA3-384", NistObjectIdentifiers.IdSha3_384);
            digestNameToOids.Add("SHA3-512", NistObjectIdentifiers.IdSha3_512);

            digestNameToOids.Add("SHAKE-128", NistObjectIdentifiers.IdShake128);
            digestNameToOids.Add("SHAKE-256", NistObjectIdentifiers.IdShake256);

            digestNameToOids.Add("GOST3411", CryptoProObjectIdentifiers.GostR3411);

            digestNameToOids.Add("MD2", PkcsObjectIdentifiers.MD2);
            digestNameToOids.Add("MD4", PkcsObjectIdentifiers.MD4);
            digestNameToOids.Add("MD5", PkcsObjectIdentifiers.MD5);

            digestNameToOids.Add("RIPEMD128", TeleTrusTObjectIdentifiers.RipeMD128);
            digestNameToOids.Add("RIPEMD160", TeleTrusTObjectIdentifiers.RipeMD160);
            digestNameToOids.Add("RIPEMD256", TeleTrusTObjectIdentifiers.RipeMD256);
        }

        public AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId)
        {
            AlgorithmIdentifier digAlgId;

            if (sigAlgId.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
            {
                digAlgId = RsassaPssParameters.GetInstance(sigAlgId.Parameters).HashAlgorithm;
            }
            else
            {
                digAlgId = new AlgorithmIdentifier((DerObjectIdentifier)digestOids[sigAlgId.Algorithm], DerNull.Instance);
            }

            return digAlgId;
        }

        public AlgorithmIdentifier find(string digAlgName)
        {
            return new AlgorithmIdentifier((DerObjectIdentifier)digestNameToOids[digAlgName], DerNull.Instance);
        }
    }

    public class CmsSignedGenerator
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

        internal IList _certs = Platform.CreateArrayList();
        internal IList _crls = Platform.CreateArrayList();
        internal IList _signers = Platform.CreateArrayList();
        internal IDictionary _digests = Platform.CreateHashtable();
        internal bool _useDerForCerts = false;
        internal bool _useDerForCrls = false;

        protected readonly SecureRandom rand;

        protected CmsSignedGenerator()
            : this(new SecureRandom())
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="rand">Instance of <c>SecureRandom</c> to use.</param>
        protected CmsSignedGenerator(
            SecureRandom rand)
        {
            this.rand = rand;
        }

        internal protected virtual IDictionary GetBaseParameters(
            DerObjectIdentifier contentType,
            AlgorithmIdentifier digAlgId,
            byte[] hash)
        {
            IDictionary param = Platform.CreateHashtable();

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
                : new DerSet(attr.ToAsn1EncodableVector());
        }

        public void AddCertificates(
            IX509Store certStore)
        {
            CollectionUtilities.AddRange(_certs, CmsUtilities.GetCertificatesFromStore(certStore));
        }

        public void AddCrls(
            IX509Store crlStore)
        {
            CollectionUtilities.AddRange(_crls, CmsUtilities.GetCrlsFromStore(crlStore));
        }

        /**
		* Add the attribute certificates contained in the passed in store to the
		* generator.
		*
		* @param store a store of Version 2 attribute certificates
		* @throws CmsException if an error occurse processing the store.
		*/
        public void AddAttributeCertificates(
            IX509Store store)
        {
            try
            {
                foreach (IX509AttributeCertificate attrCert in store.GetMatches(null))
                {
                    _certs.Add(new DerTaggedObject(false, 2,
                        AttributeCertificate.GetInstance(Asn1Object.FromByteArray(attrCert.GetEncoded()))));
                }
            }
            catch (Exception e)
            {
                throw new CmsException("error processing attribute certs", e);
            }
        }

        /**
		 * Add a store of precalculated signers to the generator.
		 *
		 * @param signerStore store of signers
		 */
        public void AddSigners(
            SignerInformationStore signerStore)
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
        public IDictionary GetGeneratedDigests()
        {
            return Platform.CreateHashtable(_digests);
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
