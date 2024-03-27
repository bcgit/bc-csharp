using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Operators.Utilities;
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

        private static readonly HashSet<DerObjectIdentifier> m_noParams = new HashSet<DerObjectIdentifier>();
        private static readonly Dictionary<string, DerObjectIdentifier> m_ecAlgorithms =
            new Dictionary<string, DerObjectIdentifier>();

        private static void AddEntries(DerObjectIdentifier oid, string digest, string encryption)
        {
            m_digestAlgs.Add(oid, digest);
            m_encryptionAlgs.Add(oid, encryption);
        }

        static CmsSignedHelper()
        {
            AddEntries(NistObjectIdentifiers.DsaWithSha224, "SHA224", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha256, "SHA256", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha384, "SHA384", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha512, "SHA512", "DSA");
            AddEntries(OiwObjectIdentifiers.DsaWithSha1, "SHA1", "DSA");
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
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha1, "SHA1", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha224, "SHA224", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha256, "SHA256", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha384, "SHA384", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha512, "SHA512", "ECDSA");
            AddEntries(X9ObjectIdentifiers.IdDsaWithSha1, "SHA1", "DSA");
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
            AddEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256", "ECGOST3410");
            AddEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512", "ECGOST3410");

            m_encryptionAlgs.Add(X9ObjectIdentifiers.IdDsa, "DSA");
            m_encryptionAlgs.Add(PkcsObjectIdentifiers.RsaEncryption, "RSA");
            m_encryptionAlgs.Add(TeleTrusTObjectIdentifiers.TeleTrusTRsaSignatureAlgorithm, "RSA");
            m_encryptionAlgs.Add(X509ObjectIdentifiers.IdEARsa, "RSA");
            m_encryptionAlgs.Add(PkcsObjectIdentifiers.IdRsassaPss, "RSAandMGF1");
            m_encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x94, "GOST3410");
            m_encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x2001, "ECGOST3410");
            m_encryptionAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410");
            m_encryptionAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410");
            m_encryptionAlgs.Add(new DerObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
            m_encryptionAlgs.Add(new DerObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
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
            m_digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD128, "RIPEMD128");
            m_digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD160, "RIPEMD160");
            m_digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD256, "RIPEMD256");
            m_digestAlgs.Add(CryptoProObjectIdentifiers.GostR3411, "GOST3411");
            m_digestAlgs.Add(new DerObjectIdentifier("1.3.6.1.4.1.5849.1.2.1"), "GOST3411");
            m_digestAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, "GOST3411-2012-256");
            m_digestAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, "GOST3411-2012-512");

            m_digestAliases.Add("SHA1", new string[]{ "SHA-1" });
            m_digestAliases.Add("SHA224", new string[]{ "SHA-224" });
            m_digestAliases.Add("SHA256", new string[]{ "SHA-256" });
            m_digestAliases.Add("SHA384", new string[]{ "SHA-384" });
            m_digestAliases.Add("SHA512", new string[]{ "SHA-512" });

            m_noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);

            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha1, X9ObjectIdentifiers.ECDsaWithSha1);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha224, X9ObjectIdentifiers.ECDsaWithSha224);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha256, X9ObjectIdentifiers.ECDsaWithSha256);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha384, X9ObjectIdentifiers.ECDsaWithSha384);
            m_ecAlgorithms.Add(CmsSignedGenerator.DigestSha512, X9ObjectIdentifiers.ECDsaWithSha512);
        }

        /**
        * Return the digest algorithm using one of the standard JCA string
        * representations rather than the algorithm identifier (if possible).
        */
        internal static string GetDigestAlgName(DerObjectIdentifier digestOid)
        {
            if (m_digestAlgs.TryGetValue(digestOid, out var name))
                return name;

            return digestOid.Id;
        }

        internal static AlgorithmIdentifier GetEncAlgorithmIdentifier(DerObjectIdentifier encOid,
            Asn1Encodable sigX509Parameters)
        {
            if (m_noParams.Contains(encOid))
                return new AlgorithmIdentifier(encOid);

            return new AlgorithmIdentifier(encOid, sigX509Parameters);
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

            return encryptionOid.Id;
        }

        internal static IDigest GetDigestInstance(string algorithm)
        {
            try
            {
                return DigestUtilities.GetDigest(algorithm);
            }
            catch (SecurityUtilityException)
            {
                // This is probably superfluous on C#, since no provider infrastructure,
                // assuming DigestUtilities already knows all the aliases
                foreach (string alias in GetDigestAliases(algorithm))
                {
                    try { return DigestUtilities.GetDigest(alias); }
                    catch (SecurityUtilityException) {}
                }
                throw;
            }
        }

        internal static ISigner GetSignatureInstance(string algorithm)
        {
            return SignerUtilities.GetSigner(algorithm);
        }

        internal static AlgorithmIdentifier FixDigestAlgID(AlgorithmIdentifier algID,
            IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            var parameters = algID.Parameters;
            if (parameters == null || DerNull.Instance.Equals(parameters))
                return digestAlgorithmFinder.Find(algID.Algorithm);

            return algID;
        }

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
    }
}
