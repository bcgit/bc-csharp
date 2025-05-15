using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.EdEC;
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
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    internal static class CmsSignedHelper
    {
        private static readonly Dictionary<DerObjectIdentifier, string> m_encryptionAlgs =
            new Dictionary<DerObjectIdentifier, string>();
        private static readonly Dictionary<DerObjectIdentifier, string> m_digestAlgs =
            new Dictionary<DerObjectIdentifier, string>();
        private static readonly Dictionary<string, string[]> m_digestAliases = new Dictionary<string, string[]>();
        private static readonly Dictionary<string, DerObjectIdentifier> m_ecAlgorithms =
            new Dictionary<string, DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> m_noParams = new HashSet<DerObjectIdentifier>();
        private static readonly Dictionary<DerObjectIdentifier, DerObjectIdentifier> m_slhDsaDigestAlgs =
            new Dictionary<DerObjectIdentifier, DerObjectIdentifier>();

        private static void AddEntries(DerObjectIdentifier oid, string digest, string encryption)
        {
            m_digestAlgs.Add(oid, digest);
            m_encryptionAlgs.Add(oid, encryption);
        }

        static CmsSignedHelper()
        {
            AddEntries(X9ObjectIdentifiers.IdDsaWithSha1, "SHA1", "DSA");
            AddEntries(OiwObjectIdentifiers.DsaWithSha1, "SHA1", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha224, "SHA224", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha256, "SHA256", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha384, "SHA384", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha512, "SHA512", "DSA");

            AddEntries(NistObjectIdentifiers.IdDsaWithSha3_224, "SHA3-224", "DSA");
            AddEntries(NistObjectIdentifiers.IdDsaWithSha3_256, "SHA3-256", "DSA");
            AddEntries(NistObjectIdentifiers.IdDsaWithSha3_384, "SHA3-384", "DSA");
            AddEntries(NistObjectIdentifiers.IdDsaWithSha3_512, "SHA3-512", "DSA");

            AddEntries(X9ObjectIdentifiers.ECDsaWithSha1, "SHA1", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha224, "SHA224", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha256, "SHA256", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha384, "SHA384", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha512, "SHA512", "ECDSA");

            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA1, "SHA1", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA224, "SHA224", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA256, "SHA256", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA384, "SHA384", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA512, "SHA512", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160", "PLAIN-ECDSA");

            AddEntries(NistObjectIdentifiers.IdEcdsaWithSha3_224, "SHA3-224", "ECDSA");
            AddEntries(NistObjectIdentifiers.IdEcdsaWithSha3_256, "SHA3-256", "ECDSA");
            AddEntries(NistObjectIdentifiers.IdEcdsaWithSha3_384, "SHA3-384", "ECDSA");
            AddEntries(NistObjectIdentifiers.IdEcdsaWithSha3_512, "SHA3-512", "ECDSA");

            AddEntries(X509ObjectIdentifiers.id_ecdsa_with_shake128, "SHAKE128", "ECDSA");
            AddEntries(X509ObjectIdentifiers.id_ecdsa_with_shake256, "SHAKE256", "ECDSA");

            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA3_224, "SHA3-224", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA3_256, "SHA3-256", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA3_384, "SHA3-384", "PLAIN-ECDSA");
            AddEntries(BsiObjectIdentifiers.ecdsa_plain_SHA3_512, "SHA3-512", "PLAIN-ECDSA");

            AddEntries(OiwObjectIdentifiers.MD4WithRsa, "MD4", "RSA");
            AddEntries(OiwObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
            AddEntries(OiwObjectIdentifiers.MD5WithRsa, "MD5", "RSA");
            AddEntries(OiwObjectIdentifiers.Sha1WithRsa, "SHA1", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD2WithRsaEncryption, "MD2", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD5WithRsaEncryption, "MD5", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha1WithRsaEncryption, "SHA1", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha224WithRsaEncryption, "SHA224", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha256WithRsaEncryption, "SHA256", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha384WithRsaEncryption, "SHA384", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512WithRsaEncryption, "SHA512", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption, "SHA512(224)", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption, "SHA512(256)", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, "SHA3-224", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, "SHA3-256", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, "SHA3-384", "RSA");
            AddEntries(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, "SHA3-512", "RSA");
            AddEntries(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128, "SHAKE128", "RSAPSS");
            AddEntries(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256, "SHAKE256", "RSAPSS");

            AddEntries(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, "RIPEMD128", "RSA");
            AddEntries(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, "RIPEMD160", "RSA");
            AddEntries(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, "RIPEMD256", "RSA");

            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");
            AddEntries(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, "GOST3411", "GOST3410");
            AddEntries(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, "GOST3411", "ECGOST3410");
            AddEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256",
                "ECGOST3410-2012-256");
            AddEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512",
                "ECGOST3410-2012-512");

            //AddEntries(GMObjectIdentifiers.sm2sign_with_rmd160, "RIPEMD160", "SM2");
            //AddEntries(GMObjectIdentifiers.sm2sign_with_sha1, "SHA1", "SM2");
            //AddEntries(GMObjectIdentifiers.sm2sign_with_sha224, "SHA224", "SM2");
            AddEntries(GMObjectIdentifiers.sm2sign_with_sha256, "SHA256", "SM2");
            //AddEntries(GMObjectIdentifiers.sm2sign_with_sha384, "SHA384", "SM2");
            //AddEntries(GMObjectIdentifiers.sm2sign_with_sha512, "SHA512", "SM2");
            AddEntries(GMObjectIdentifiers.sm2sign_with_sm3, "SM3", "SM2");

            m_encryptionAlgs.Add(X9ObjectIdentifiers.IdDsa, "DSA");
            m_encryptionAlgs.Add(PkcsObjectIdentifiers.RsaEncryption, "RSA");
            m_encryptionAlgs.Add(TeleTrusTObjectIdentifiers.rsaSignature, "RSA");
            m_encryptionAlgs.Add(X509ObjectIdentifiers.IdEARsa, "RSA");
            m_encryptionAlgs.Add(PkcsObjectIdentifiers.IdRsassaPss, "RSAandMGF1");
            m_encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x94, "GOST3410");
            m_encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x2001, "ECGOST3410");
            m_encryptionAlgs.Add(new DerObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
            m_encryptionAlgs.Add(new DerObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
            m_encryptionAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
            m_encryptionAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
            m_encryptionAlgs.Add(X9ObjectIdentifiers.IdECPublicKey, "ECDSA");

            m_digestAlgs.Add(PkcsObjectIdentifiers.MD2, "MD2");
            m_digestAlgs.Add(PkcsObjectIdentifiers.MD4, "MD4");
            m_digestAlgs.Add(PkcsObjectIdentifiers.MD5, "MD5");
            m_digestAlgs.Add(OiwObjectIdentifiers.IdSha1, "SHA1");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha224, "SHA224");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha256, "SHA256");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha384, "SHA384");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha512, "SHA512");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha512_224, "SHA512(224)");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha512_256, "SHA512(256)");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha3_224, "SHA3-224");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha3_256, "SHA3-256");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha3_384, "SHA3-384");
            m_digestAlgs.Add(NistObjectIdentifiers.IdSha3_512, "SHA3-512");
            m_digestAlgs.Add(NistObjectIdentifiers.IdShake128, "SHAKE128");
            m_digestAlgs.Add(NistObjectIdentifiers.IdShake256, "SHAKE256");
            m_digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD128, "RIPEMD128");
            m_digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD160, "RIPEMD160");
            m_digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD256, "RIPEMD256");
            m_digestAlgs.Add(CryptoProObjectIdentifiers.GostR3411, "GOST3411");
            m_digestAlgs.Add(new DerObjectIdentifier("1.3.6.1.4.1.5849.1.2.1"), "GOST3411");
            m_digestAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, "GOST3411-2012-256");
            m_digestAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, "GOST3411-2012-512");
            m_digestAlgs.Add(GMObjectIdentifiers.sm3, "SM3");

            m_digestAliases.Add("SHA1", new string[]{ "SHA-1" });
            m_digestAliases.Add("SHA224", new string[]{ "SHA-224" });
            m_digestAliases.Add("SHA256", new string[]{ "SHA-256" });
            m_digestAliases.Add("SHA384", new string[]{ "SHA-384" });
            m_digestAliases.Add("SHA512", new string[]{ "SHA-512" });

            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha1, X9ObjectIdentifiers.ECDsaWithSha1);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha224, X9ObjectIdentifiers.ECDsaWithSha224);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha256, X9ObjectIdentifiers.ECDsaWithSha256);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha384, X9ObjectIdentifiers.ECDsaWithSha384);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha512, X9ObjectIdentifiers.ECDsaWithSha512);

            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha3_224, NistObjectIdentifiers.IdEcdsaWithSha3_224);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha3_256, NistObjectIdentifiers.IdEcdsaWithSha3_256);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha3_384, NistObjectIdentifiers.IdEcdsaWithSha3_384);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha3_512, NistObjectIdentifiers.IdEcdsaWithSha3_512);

            m_noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            m_noParams.Add(OiwObjectIdentifiers.DsaWithSha1);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha224);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha256);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha384);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha512);

            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_224);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_256);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_384);
            m_noParams.Add(NistObjectIdentifiers.IdDsaWithSha3_512);

            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);

            //m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA1);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA224);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA256);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA384);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA512);

            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384);
            m_noParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512);

            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_224);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_256);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_384);
            m_noParams.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_512);

            m_noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            m_noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            m_noParams.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            m_noParams.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_rmd160);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha1);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha224);
            m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha256);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha384);
            //m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sha512);
            m_noParams.Add(GMObjectIdentifiers.sm2sign_with_sm3);

            m_noParams.Add(EdECObjectIdentifiers.id_Ed25519);
            m_noParams.Add(EdECObjectIdentifiers.id_Ed448);

            m_noParams.Add(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
            m_noParams.Add(X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
            m_noParams.Add(X509ObjectIdentifiers.id_ecdsa_with_shake128);
            m_noParams.Add(X509ObjectIdentifiers.id_ecdsa_with_shake256);

            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_sha2_128f, NistObjectIdentifiers.IdSha256);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_sha2_128s, NistObjectIdentifiers.IdSha256);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_sha2_192f, NistObjectIdentifiers.IdSha512);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_sha2_192s, NistObjectIdentifiers.IdSha512);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_sha2_256f, NistObjectIdentifiers.IdSha512);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_sha2_256s, NistObjectIdentifiers.IdSha512);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_shake_128f, NistObjectIdentifiers.IdShake128);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_shake_128s, NistObjectIdentifiers.IdShake128);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_shake_192f, NistObjectIdentifiers.IdShake256);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_shake_192s, NistObjectIdentifiers.IdShake256);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_shake_256f, NistObjectIdentifiers.IdShake256);
            m_slhDsaDigestAlgs.Add(NistObjectIdentifiers.id_slh_dsa_shake_256s, NistObjectIdentifiers.IdShake256);
        }

        /**
        * Return the digest algorithm using one of the standard JCA string
        * representations rather than the algorithm identifier (if possible).
        */
        internal static string GetDigestAlgName(DerObjectIdentifier digestOid)
        {
            if (m_digestAlgs.TryGetValue(digestOid, out var name))
                return name;

            return digestOid.GetID();
        }

        internal static AlgorithmIdentifier GetSigAlgID(DerObjectIdentifier sigAlgOid, Asn1Encodable sigAlgParams)
        {
            if (m_noParams.Contains(sigAlgOid))
                return new AlgorithmIdentifier(sigAlgOid);

            return new AlgorithmIdentifier(sigAlgOid, sigAlgParams);
        }

        internal static string[] GetDigestAliases(string algName)
        {
            return m_digestAliases.TryGetValue(algName, out var aliases) ? (string[])aliases.Clone() : new string[0];
        }

        /**
        * Return the digest encryption algorithm using one of the standard
        * JCA string representations rather than the algorithm identifier (if
        * possible).
        */
        internal static string GetEncryptionAlgName(DerObjectIdentifier encryptionOid)
        {
            if (m_encryptionAlgs.TryGetValue(encryptionOid, out var name))
                return name;

            return encryptionOid.GetID();
        }

        internal static IDigest GetDigestInstance(string algorithm) => DigestUtilities.GetDigest(algorithm);

        internal static ISigner GetSignatureInstance(string algorithm) => SignerUtilities.GetSigner(algorithm);

        internal static DerObjectIdentifier GetEncOid(AsymmetricKeyParameter key, string digestOID)
        {
            DerObjectIdentifier encOid = null;

            if (key is RsaKeyParameters rsaKeyParameters)
            {
                if (!rsaKeyParameters.IsPrivate)
                    throw new ArgumentException("Expected RSA private key");

                encOid = PkcsObjectIdentifiers.RsaEncryption;
            }
            else if (key is DsaPrivateKeyParameters)
            {
                if (digestOID.Equals(CmsSignedGenerator.DigestSha1))
                {
                    encOid = X9ObjectIdentifiers.IdDsaWithSha1;
                }
                else if (digestOID.Equals(CmsSignedGenerator.DigestSha224))
                {
                    encOid = NistObjectIdentifiers.DsaWithSha224;
                }
                else if (digestOID.Equals(CmsSignedGenerator.DigestSha256))
                {
                    encOid = NistObjectIdentifiers.DsaWithSha256;
                }
                else if (digestOID.Equals(CmsSignedGenerator.DigestSha384))
                {
                    encOid = NistObjectIdentifiers.DsaWithSha384;
                }
                else if (digestOID.Equals(CmsSignedGenerator.DigestSha512))
                {
                    encOid = NistObjectIdentifiers.DsaWithSha512;
                }
                else
                {
                    throw new ArgumentException("can't mix DSA with anything but SHA1/SHA2");
                }
            }
            else if (key is ECPrivateKeyParameters ecPrivKey)
            {
                string algName = ecPrivKey.AlgorithmName;

                if (algName == "ECGOST3410")
                {
                    encOid = CryptoProObjectIdentifiers.GostR3410x2001;
                }
                else if (ecPrivKey.Parameters is ECGost3410Parameters ecGost3410Parameters)
                {
                    var digestParamSet = ecGost3410Parameters.DigestParamSet;
                    if (digestParamSet.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256))
                    {
                        encOid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    }
                    else if (digestParamSet.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512))
                    {
                        encOid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                    }
                    else
                    {
                        throw new ArgumentException("can't determine GOST3410 algorithm");
                    }
                }
                else
                {
                    // TODO Should we insist on algName being one of "EC" or "ECDSA", as Java does?
                    if (!m_ecAlgorithms.TryGetValue(digestOID, out encOid))
                        throw new ArgumentException("can't mix ECDSA with anything but SHA family digests");
                }
            }
            else if (key is Gost3410PrivateKeyParameters)
            {
                encOid = CryptoProObjectIdentifiers.GostR3410x94;
            }
            else
            {
                throw new ArgumentException("Unknown algorithm in CmsSignedGenerator.GetEncOid");
            }

            return encOid;
        }

        internal static IStore<X509V2AttributeCertificate> GetAttributeCertificates(Asn1Set attrCertSet)
        {
            var contents = new List<X509V2AttributeCertificate>();
            if (attrCertSet != null)
            {
                foreach (Asn1Encodable ae in attrCertSet)
                {
                    if (ae.ToAsn1Object() is Asn1TaggedObject taggedObject && taggedObject.HasContextTag(2))
                    {
                        var attributeCertificate = AttributeCertificate.GetInstance(taggedObject, false);

                        contents.Add(new X509V2AttributeCertificate(attributeCertificate));
                    }
                }
            }
            return CollectionUtilities.CreateStore(contents);
        }

        internal static IStore<X509Certificate> GetCertificates(Asn1Set certSet)
        {
            var contents = new List<X509Certificate>();
            if (certSet != null)
            {
                foreach (Asn1Encodable ae in certSet)
                {
                    if (ae is X509CertificateStructure c)
                    {
                        contents.Add(new X509Certificate(c));
                    }
                    else if (ae.ToAsn1Object() is Asn1Sequence s)
                    {
                        contents.Add(new X509Certificate(X509CertificateStructure.GetInstance(s)));
                    }
                }
            }
            return CollectionUtilities.CreateStore(contents);
        }

        internal static IStore<X509Crl> GetCrls(Asn1Set crlSet)
        {
            var contents = new List<X509Crl>();
            if (crlSet != null)
            {
                foreach (Asn1Encodable ae in crlSet)
                {
                    if (ae is CertificateList c)
                    {
                        contents.Add(new X509Crl(c));
                    }
                    else if (ae.ToAsn1Object() is Asn1Sequence s)
                    {
                        contents.Add(new X509Crl(CertificateList.GetInstance(s)));
                    }
                }
            }
            return CollectionUtilities.CreateStore(contents);
        }

        internal static IStore<Asn1Encodable> GetOtherRevInfos(Asn1Set crlSet, DerObjectIdentifier infoFormat)
        {
            var contents = new List<Asn1Encodable>();
            if (crlSet != null && infoFormat != null)
            {
                foreach (Asn1Encodable ae in crlSet)
                {
                    if (ae.ToAsn1Object() is Asn1TaggedObject taggedObject && taggedObject.HasContextTag(1))
                    {
                        var otherRevocationInfoFormat = OtherRevocationInfoFormat.GetInstance(taggedObject, false);

                        if (infoFormat.Equals(otherRevocationInfoFormat.InfoFormat))
                        {
                            contents.Add(otherRevocationInfoFormat.Info);
                        }
                    }
                }
            }
            return CollectionUtilities.CreateStore(contents);
        }

        internal static DerObjectIdentifier GetSlhDsaDigestOid(DerObjectIdentifier slhDsaOid) =>
            m_slhDsaDigestAlgs[slhDsaOid];
    }
}
