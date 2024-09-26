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
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Operators.Utilities
{
    public class DefaultDigestAlgorithmFinder
        : IDigestAlgorithmFinder
    {
        public static readonly DefaultDigestAlgorithmFinder Instance = new DefaultDigestAlgorithmFinder();

        private static readonly Dictionary<DerObjectIdentifier, DerObjectIdentifier> DigestOids =
            new Dictionary<DerObjectIdentifier, DerObjectIdentifier>();
        private static readonly Dictionary<string, DerObjectIdentifier> DigestNameToOids =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, AlgorithmIdentifier> DigestOidToAlgIDs =
            new Dictionary<DerObjectIdentifier, AlgorithmIdentifier>();

        // signatures that use SHAKE-256
        private static readonly HashSet<DerObjectIdentifier> Shake256Oids = new HashSet<DerObjectIdentifier>();

        static DefaultDigestAlgorithmFinder()
        {
            //
            // digests
            //
            DigestOids.Add(OiwObjectIdentifiers.DsaWithSha1, OiwObjectIdentifiers.IdSha1);
            DigestOids.Add(OiwObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            DigestOids.Add(OiwObjectIdentifiers.MD4WithRsa, PkcsObjectIdentifiers.MD4);
            DigestOids.Add(OiwObjectIdentifiers.MD5WithRsa, PkcsObjectIdentifiers.MD5);
            DigestOids.Add(OiwObjectIdentifiers.Sha1WithRsa, OiwObjectIdentifiers.IdSha1);

            DigestOids.Add(PkcsObjectIdentifiers.Sha224WithRsaEncryption, NistObjectIdentifiers.IdSha224);
            DigestOids.Add(PkcsObjectIdentifiers.Sha256WithRsaEncryption, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(PkcsObjectIdentifiers.Sha384WithRsaEncryption, NistObjectIdentifiers.IdSha384);
            DigestOids.Add(PkcsObjectIdentifiers.Sha512WithRsaEncryption, NistObjectIdentifiers.IdSha512);
            DigestOids.Add(PkcsObjectIdentifiers.Sha512_224WithRSAEncryption, NistObjectIdentifiers.IdSha512_224);
            DigestOids.Add(PkcsObjectIdentifiers.Sha512_256WithRSAEncryption, NistObjectIdentifiers.IdSha512_256);
            DigestOids.Add(PkcsObjectIdentifiers.MD2WithRsaEncryption, PkcsObjectIdentifiers.MD2);
            DigestOids.Add(PkcsObjectIdentifiers.MD4WithRsaEncryption, PkcsObjectIdentifiers.MD4);
            DigestOids.Add(PkcsObjectIdentifiers.MD5WithRsaEncryption, PkcsObjectIdentifiers.MD5);
            DigestOids.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption, OiwObjectIdentifiers.IdSha1);

            DigestOids.Add(X9ObjectIdentifiers.ECDsaWithSha1, OiwObjectIdentifiers.IdSha1);
            DigestOids.Add(X9ObjectIdentifiers.ECDsaWithSha224, NistObjectIdentifiers.IdSha224);
            DigestOids.Add(X9ObjectIdentifiers.ECDsaWithSha256, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(X9ObjectIdentifiers.ECDsaWithSha384, NistObjectIdentifiers.IdSha384);
            DigestOids.Add(X9ObjectIdentifiers.ECDsaWithSha512, NistObjectIdentifiers.IdSha512);
            DigestOids.Add(X9ObjectIdentifiers.IdDsaWithSha1, OiwObjectIdentifiers.IdSha1);

            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA1, OiwObjectIdentifiers.IdSha1);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA224, NistObjectIdentifiers.IdSha224);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA256, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA384, NistObjectIdentifiers.IdSha384);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA512, NistObjectIdentifiers.IdSha512);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_224, NistObjectIdentifiers.IdSha3_224);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_256, NistObjectIdentifiers.IdSha3_256);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_384, NistObjectIdentifiers.IdSha3_384);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_SHA3_512, NistObjectIdentifiers.IdSha3_512);
            DigestOids.Add(BsiObjectIdentifiers.ecdsa_plain_RIPEMD160, TeleTrusTObjectIdentifiers.RipeMD160);

            DigestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, OiwObjectIdentifiers.IdSha1);
            DigestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, NistObjectIdentifiers.IdSha224);
            DigestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, NistObjectIdentifiers.IdSha384);
            DigestOids.Add(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, NistObjectIdentifiers.IdSha512);

            DigestOids.Add(NistObjectIdentifiers.DsaWithSha224, NistObjectIdentifiers.IdSha224);
            DigestOids.Add(NistObjectIdentifiers.DsaWithSha256, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(NistObjectIdentifiers.DsaWithSha384, NistObjectIdentifiers.IdSha384);
            DigestOids.Add(NistObjectIdentifiers.DsaWithSha512, NistObjectIdentifiers.IdSha512);

            DigestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, NistObjectIdentifiers.IdSha3_224);
            DigestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, NistObjectIdentifiers.IdSha3_256);
            DigestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, NistObjectIdentifiers.IdSha3_384);
            DigestOids.Add(NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, NistObjectIdentifiers.IdSha3_512);
            DigestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_224, NistObjectIdentifiers.IdSha3_224);
            DigestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_256, NistObjectIdentifiers.IdSha3_256);
            DigestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_384, NistObjectIdentifiers.IdSha3_384);
            DigestOids.Add(NistObjectIdentifiers.IdDsaWithSha3_512, NistObjectIdentifiers.IdSha3_512);
            DigestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224, NistObjectIdentifiers.IdSha3_224);
            DigestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256, NistObjectIdentifiers.IdSha3_256);
            DigestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384, NistObjectIdentifiers.IdSha3_384);
            DigestOids.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512, NistObjectIdentifiers.IdSha3_512);

            DigestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, TeleTrusTObjectIdentifiers.RipeMD128);
            DigestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, TeleTrusTObjectIdentifiers.RipeMD160);
            DigestOids.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, TeleTrusTObjectIdentifiers.RipeMD256);

            DigestOids.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, CryptoProObjectIdentifiers.GostR3411);
            DigestOids.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, CryptoProObjectIdentifiers.GostR3411);
            DigestOids.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            DigestOids.Add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

#pragma warning disable CS0618 // Type or member is obsolete
            DigestOids.Add(BCObjectIdentifiers.sphincs256_with_SHA3_512, NistObjectIdentifiers.IdSha3_512);
            DigestOids.Add(BCObjectIdentifiers.sphincs256_with_SHA512, NistObjectIdentifiers.IdSha512);
#pragma warning restore CS0618 // Type or member is obsolete

            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, NistObjectIdentifiers.IdShake256);

            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, NistObjectIdentifiers.IdSha256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, NistObjectIdentifiers.IdShake256);

            DigestOids.Add(BCObjectIdentifiers.falcon, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.falcon_512, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.falcon_1024, NistObjectIdentifiers.IdShake256);

            DigestOids.Add(BCObjectIdentifiers.picnic_signature, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(BCObjectIdentifiers.picnic_with_sha512, NistObjectIdentifiers.IdSha512);
            DigestOids.Add(BCObjectIdentifiers.picnic_with_sha3_512, NistObjectIdentifiers.IdSha3_512);
            DigestOids.Add(BCObjectIdentifiers.picnic_with_shake256, NistObjectIdentifiers.IdShake256);

            //DigestOids.Add(GMObjectIdentifiers.sm2sign_with_rmd160, TeleTrusTObjectIdentifiers.RipeMD160);
            //DigestOids.Add(GMObjectIdentifiers.sm2sign_with_sha1, OiwObjectIdentifiers.IdSha1);
            //DigestOids.Add(GMObjectIdentifiers.sm2sign_with_sha224, NistObjectIdentifiers.IdSha224);
            DigestOids.Add(GMObjectIdentifiers.sm2sign_with_sha256, NistObjectIdentifiers.IdSha256);
            //DigestOids.Add(GMObjectIdentifiers.sm2sign_with_sha384, NistObjectIdentifiers.IdSha384);
            //DigestOids.Add(GMObjectIdentifiers.sm2sign_with_sha512, NistObjectIdentifiers.IdSha512);
            DigestOids.Add(GMObjectIdentifiers.sm2sign_with_sm3, GMObjectIdentifiers.sm3);

            DigestOids.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE128, NistObjectIdentifiers.IdShake128);
            DigestOids.Add(CmsObjectIdentifiers.id_RSASSA_PSS_SHAKE256, NistObjectIdentifiers.IdShake256);
            DigestOids.Add(CmsObjectIdentifiers.id_ecdsa_with_shake128, NistObjectIdentifiers.IdShake128);
            DigestOids.Add(CmsObjectIdentifiers.id_ecdsa_with_shake256, NistObjectIdentifiers.IdShake256);

            DigestNameToOids.Add("SHA-1", OiwObjectIdentifiers.IdSha1);
            DigestNameToOids.Add("SHA-224", NistObjectIdentifiers.IdSha224);
            DigestNameToOids.Add("SHA-256", NistObjectIdentifiers.IdSha256);
            DigestNameToOids.Add("SHA-384", NistObjectIdentifiers.IdSha384);
            DigestNameToOids.Add("SHA-512", NistObjectIdentifiers.IdSha512);
            DigestNameToOids.Add("SHA-512-224", NistObjectIdentifiers.IdSha512_224);
            DigestNameToOids.Add("SHA-512/224", NistObjectIdentifiers.IdSha512_224);
            DigestNameToOids.Add("SHA-512(224)", NistObjectIdentifiers.IdSha512_224);
            DigestNameToOids.Add("SHA-512-256", NistObjectIdentifiers.IdSha512_256);
            DigestNameToOids.Add("SHA-512/256", NistObjectIdentifiers.IdSha512_256);
            DigestNameToOids.Add("SHA-512(256)", NistObjectIdentifiers.IdSha512_256);

            DigestNameToOids.Add("SHA1", OiwObjectIdentifiers.IdSha1);
            DigestNameToOids.Add("SHA224", NistObjectIdentifiers.IdSha224);
            DigestNameToOids.Add("SHA256", NistObjectIdentifiers.IdSha256);
            DigestNameToOids.Add("SHA384", NistObjectIdentifiers.IdSha384);
            DigestNameToOids.Add("SHA512", NistObjectIdentifiers.IdSha512);
            DigestNameToOids.Add("SHA512-224", NistObjectIdentifiers.IdSha512_224);
            DigestNameToOids.Add("SHA512/224", NistObjectIdentifiers.IdSha512_224);
            DigestNameToOids.Add("SHA512(224)", NistObjectIdentifiers.IdSha512_224);
            DigestNameToOids.Add("SHA512-256", NistObjectIdentifiers.IdSha512_256);
            DigestNameToOids.Add("SHA512/256", NistObjectIdentifiers.IdSha512_256);
            DigestNameToOids.Add("SHA512(256)", NistObjectIdentifiers.IdSha512_256);

            DigestNameToOids.Add("SHA3-224", NistObjectIdentifiers.IdSha3_224);
            DigestNameToOids.Add("SHA3-256", NistObjectIdentifiers.IdSha3_256);
            DigestNameToOids.Add("SHA3-384", NistObjectIdentifiers.IdSha3_384);
            DigestNameToOids.Add("SHA3-512", NistObjectIdentifiers.IdSha3_512);

            DigestNameToOids.Add("SHAKE128", NistObjectIdentifiers.IdShake128);
            DigestNameToOids.Add("SHAKE256", NistObjectIdentifiers.IdShake256);
            DigestNameToOids.Add("SHAKE-128", NistObjectIdentifiers.IdShake128);
            DigestNameToOids.Add("SHAKE-256", NistObjectIdentifiers.IdShake256);

            DigestNameToOids.Add("GOST3411", CryptoProObjectIdentifiers.GostR3411);
            DigestNameToOids.Add("GOST3411-2012-256", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            DigestNameToOids.Add("GOST3411-2012-512", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

            DigestNameToOids.Add("MD2", PkcsObjectIdentifiers.MD2);
            DigestNameToOids.Add("MD4", PkcsObjectIdentifiers.MD4);
            DigestNameToOids.Add("MD5", PkcsObjectIdentifiers.MD5);

            DigestNameToOids.Add("RIPEMD128", TeleTrusTObjectIdentifiers.RipeMD128);
            DigestNameToOids.Add("RIPEMD160", TeleTrusTObjectIdentifiers.RipeMD160);
            DigestNameToOids.Add("RIPEMD256", TeleTrusTObjectIdentifiers.RipeMD256);

            DigestNameToOids.Add("SM3", GMObjectIdentifiers.sm3);

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

            Shake256Oids.Add(EdECObjectIdentifiers.id_Ed448);

#pragma warning disable CS0618 // Type or member is obsolete
            Shake256Oids.Add(BCObjectIdentifiers.dilithium2);
            Shake256Oids.Add(BCObjectIdentifiers.dilithium3);
            Shake256Oids.Add(BCObjectIdentifiers.dilithium5);
            Shake256Oids.Add(BCObjectIdentifiers.dilithium2_aes);
            Shake256Oids.Add(BCObjectIdentifiers.dilithium3_aes);
            Shake256Oids.Add(BCObjectIdentifiers.dilithium5_aes);
#pragma warning restore CS0618 // Type or member is obsolete

            Shake256Oids.Add(BCObjectIdentifiers.falcon_512);
            Shake256Oids.Add(BCObjectIdentifiers.falcon_1024);
        }

        private static void AddDigestAlgID(DerObjectIdentifier oid, bool withNullParams) =>
            DigestOidToAlgIDs.Add(oid, new AlgorithmIdentifier(oid, withNullParams ? DerNull.Instance : null));

        protected DefaultDigestAlgorithmFinder()
        {
        }

        public virtual AlgorithmIdentifier Find(AlgorithmIdentifier signatureAlgorithm)
        {
            DerObjectIdentifier signatureOid = signatureAlgorithm.Algorithm;

            if (Shake256Oids.Contains(signatureOid))
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256Len, new DerInteger(512));

            DerObjectIdentifier digestOid;
            if (PkcsObjectIdentifiers.IdRsassaPss.Equals(signatureOid))
            {
                digestOid = RsassaPssParameters.GetInstance(signatureAlgorithm.Parameters).HashAlgorithm.Algorithm;
            }
            else if (EdECObjectIdentifiers.id_Ed25519.Equals(signatureOid))
            {
                digestOid = NistObjectIdentifiers.IdSha512;
            }
            else if (PkcsObjectIdentifiers.IdAlgHssLmsHashsig.Equals(signatureOid))
            {
                digestOid = NistObjectIdentifiers.IdSha256;
            }
            else
            {
                digestOid = CollectionUtilities.GetValueOrNull(DigestOids, signatureOid);
            }

            return Find(digestOid);
        }

        public virtual AlgorithmIdentifier Find(DerObjectIdentifier digestOid)
        {
            if (digestOid == null)
                throw new ArgumentNullException(nameof(digestOid));

            if (DigestOidToAlgIDs.TryGetValue(digestOid, out var digestAlgorithm))
                return digestAlgorithm;

            return new AlgorithmIdentifier(digestOid);
        }

        public virtual AlgorithmIdentifier Find(string digestName)
        {
            if (DigestNameToOids.TryGetValue(digestName, out var digestOid) ||
                DerObjectIdentifier.TryFromID(digestName, out digestOid))
            {
                return Find(digestOid);
            }

            return null;
        }
    }
}
