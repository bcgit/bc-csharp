using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Utility class for creating IBasicAgreement objects from their names/Oids
    /// </remarks>
    public static class AgreementUtilities
    {
        private static readonly Dictionary<string, string> AlgorithmMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();

        static AgreementUtilities()
        {
            AlgorithmMap.Add("DIFFIEHELLMAN", "DH");

            AlgorithmMap.Add("ECCDH", "ECDHC");

            // 'DHWITHSHA1KDF' retained for backward compatibility
            AlgorithmMap.Add("DHWITHSHA1KDF", "ECDHWITHSHA1KDF");
            AlgorithmOidMap[X9ObjectIdentifiers.DHSinglePassStdDHSha1KdfScheme] = "ECDHWITHSHA1KDF";
            AlgorithmOidMap[X9ObjectIdentifiers.DHSinglePassCofactorDHSha1KdfScheme] = "ECCDHWITHSHA1KDF";
            AlgorithmOidMap[X9ObjectIdentifiers.MqvSinglePassSha1KdfScheme] = "ECMQVWITHSHA1KDF";

            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme] = "ECDHWITHSHA224KDF";
            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme] = "ECCDHWITHSHA224KDF";
            AlgorithmOidMap[SecObjectIdentifiers.mqvSinglePass_sha224kdf_scheme] = "ECMQVWITHSHA224KDF";

            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme] = "ECDHWITHSHA256KDF";
            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme] = "ECCDHWITHSHA256KDF";
            AlgorithmOidMap[SecObjectIdentifiers.mqvSinglePass_sha256kdf_scheme] = "ECMQVWITHSHA256KDF";

            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme] = "ECDHWITHSHA384KDF";
            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme] = "ECCDHWITHSHA384KDF";
            AlgorithmOidMap[SecObjectIdentifiers.mqvSinglePass_sha384kdf_scheme] = "ECMQVWITHSHA384KDF";

            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme] = "ECDHWITHSHA512KDF";
            AlgorithmOidMap[SecObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme] = "ECCDHWITHSHA512KDF";
            AlgorithmOidMap[SecObjectIdentifiers.mqvSinglePass_sha512kdf_scheme] = "ECMQVWITHSHA512KDF";

            AlgorithmOidMap[EdECObjectIdentifiers.id_X25519] = "X25519";
            AlgorithmOidMap[EdECObjectIdentifiers.id_X448] = "X448";

            AlgorithmMap.Add("GOST-3410-2001", "ECGOST3410");
            AlgorithmOidMap.Add(CryptoProObjectIdentifiers.GostR3410x2001, "ECGOST3410");
            AlgorithmOidMap[CryptoProObjectIdentifiers.GostR3410x2001CryptoProESDH] = "ECGOST3410";

            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256] = "ECGOST3410-2012-256";
            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256] = "ECGOST3410-2012-256";

            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512] = "ECGOST3410-2012-512";
            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512] = "ECGOST3410-2012-512";

#if DEBUG
            foreach (var key in AlgorithmMap.Keys)
            {
                if (DerObjectIdentifier.TryFromID(key, out var ignore))
                    throw new Exception("OID mapping belongs in AlgorithmOidMap: " + key);
            }

            var mechanisms = new HashSet<string>(AlgorithmMap.Values);
            mechanisms.UnionWith(AlgorithmOidMap.Values);

            foreach (var mechanism in mechanisms)
            {
                if (AlgorithmMap.TryGetValue(mechanism, out var check))
                {
                    if (mechanism != check)
                        throw new Exception("Mechanism mapping MUST be to self: " + mechanism);
                }
                else
                {
                    if (!mechanism.Equals(mechanism.ToUpperInvariant()))
                        throw new Exception("Unmapped mechanism MUST be uppercase: " + mechanism);
                }
            }
#endif
        }

        public static string GetAlgorithmName(DerObjectIdentifier oid) =>
            CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);

        public static IBasicAgreement GetBasicAgreement(DerObjectIdentifier oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (AlgorithmOidMap.TryGetValue(oid, out var mechanism))
            {
                var basicAgreement = GetBasicAgreementForMechanism(mechanism);
                if (basicAgreement != null)
                    return basicAgreement;
            }

            throw new SecurityUtilityException("Basic Agreement OID not recognised.");
        }

        public static IBasicAgreement GetBasicAgreement(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var basicAgreement = GetBasicAgreementForMechanism(mechanism);
            if (basicAgreement != null)
                return basicAgreement;

            throw new SecurityUtilityException("Basic Agreement " + algorithm + " not recognised.");
        }

        private static IBasicAgreement GetBasicAgreementForMechanism(string mechanism)
        {
            if (mechanism == "DH")
                return new DHBasicAgreement();

            if (mechanism == "ECDH")
                return new ECDHBasicAgreement();

            if (mechanism == "ECDHC")
                return new ECDHCBasicAgreement();

            if (mechanism == "ECMQV")
                return new ECMqvBasicAgreement();

            return null;
        }

        public static IBasicAgreement GetBasicAgreementWithKdf(DerObjectIdentifier agreeAlgOid,
            DerObjectIdentifier wrapAlgOid)
        {
            return GetBasicAgreementWithKdf(agreeAlgOid, wrapAlgOid?.Id);
        }

        // TODO[api] Change parameter name to 'agreeAlgOid'
        public static IBasicAgreement GetBasicAgreementWithKdf(DerObjectIdentifier oid, string wrapAlgorithm)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));
            if (wrapAlgorithm == null)
                throw new ArgumentNullException(nameof(wrapAlgorithm));

            if (AlgorithmOidMap.TryGetValue(oid, out var mechanism))
            {
                var basicAgreement = GetBasicAgreementWithKdfForMechanism(mechanism, wrapAlgorithm);
                if (basicAgreement != null)
                    return basicAgreement;
            }

            throw new SecurityUtilityException("Basic Agreement (with KDF) OID not recognised.");
        }

        public static IBasicAgreement GetBasicAgreementWithKdf(string agreeAlgorithm, string wrapAlgorithm)
        {
            if (agreeAlgorithm == null)
                throw new ArgumentNullException(nameof(agreeAlgorithm));
            if (wrapAlgorithm == null)
                throw new ArgumentNullException(nameof(wrapAlgorithm));

            string mechanism = GetMechanism(agreeAlgorithm) ?? agreeAlgorithm.ToUpperInvariant();

            var basicAgreement = GetBasicAgreementWithKdfForMechanism(mechanism, wrapAlgorithm);
            if (basicAgreement != null)
                return basicAgreement;

            throw new SecurityUtilityException("Basic Agreement (with KDF) " + agreeAlgorithm + " not recognised.");
        }

        private static IBasicAgreement GetBasicAgreementWithKdfForMechanism(string mechanism, string wrapAlgorithm)
        {
            if (mechanism == "ECDHWITHSHA1KDF")
                return new ECDHWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-1"));
            if (mechanism == "ECDHWITHSHA224KDF")
                return new ECDHWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-224"));
            if (mechanism == "ECDHWITHSHA256KDF")
                return new ECDHWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-256"));
            if (mechanism == "ECDHWITHSHA384KDF")
                return new ECDHWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-384"));
            if (mechanism == "ECDHWITHSHA512KDF")
                return new ECDHWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-512"));

            if (mechanism == "ECCDHWITHSHA1KDF")
                return new ECDHCWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-1"));
            if (mechanism == "ECCDHWITHSHA224KDF")
                return new ECDHCWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-224"));
            if (mechanism == "ECCDHWITHSHA256KDF")
                return new ECDHCWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-256"));
            if (mechanism == "ECCDHWITHSHA384KDF")
                return new ECDHCWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-384"));
            if (mechanism == "ECCDHWITHSHA512KDF")
                return new ECDHCWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-512"));

            if (mechanism == "ECMQVWITHSHA1KDF")
                return new ECMqvWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-1"));
            if (mechanism == "ECMQVWITHSHA224KDF")
                return new ECMqvWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-224"));
            if (mechanism == "ECMQVWITHSHA256KDF")
                return new ECMqvWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-256"));
            if (mechanism == "ECMQVWITHSHA384KDF")
                return new ECMqvWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-384"));
            if (mechanism == "ECMQVWITHSHA512KDF")
                return new ECMqvWithKdfBasicAgreement(wrapAlgorithm, CreateECDHKekGenerator("SHA-512"));

            return null;
        }

        public static IRawAgreement GetRawAgreement(DerObjectIdentifier oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (AlgorithmOidMap.TryGetValue(oid, out var mechanism))
            {
                var rawAgreement = GetRawAgreementForMechanism(mechanism);
                if (rawAgreement != null)
                    return rawAgreement;
            }

            throw new SecurityUtilityException("Raw Agreement OID not recognised.");
        }
 
        public static IRawAgreement GetRawAgreement(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var rawAgreement = GetRawAgreementForMechanism(mechanism);
            if (rawAgreement != null)
                return rawAgreement;

            throw new SecurityUtilityException("Raw Agreement " + algorithm + " not recognised.");
        }

        private static IRawAgreement GetRawAgreementForMechanism(string mechanism)
        {
            if (mechanism == "X25519")
                return new X25519Agreement();

            if (mechanism == "X448")
                return new X448Agreement();

            if (mechanism == "ECGOST3410")
                return CreateECVkoAgreeement("GOST3411");

            if (mechanism == "ECGOST3410-2012-256")
                return CreateECVkoAgreeement("GOST3411-2012-256");

            if (mechanism == "ECGOST3410-2012-512")
                return CreateECVkoAgreeement("GOST3411-2012-512");

            return null;
        }

        private static string GetMechanism(string algorithm)
        {
            if (AlgorithmMap.TryGetValue(algorithm, out var mechanism1))
                return mechanism1;

            if (DerObjectIdentifier.TryFromID(algorithm, out var oid))
            {
                if (AlgorithmOidMap.TryGetValue(oid, out var mechanism2))
                    return mechanism2;
            }

            return null;
        }

        private static IDerivationFunction CreateECDHKekGenerator(string digestName) =>
            new ECDHKekGenerator(DigestUtilities.GetDigest(digestName));

        private static IRawAgreement CreateECVkoAgreeement(string digestName) =>
            new ECVkoAgreement(DigestUtilities.GetDigest(digestName));
    }
}
