using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Utility class for creating IBasicAgreement objects from their names/Oids
    /// </remarks>
    public static class AgreementUtilities
	{
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();

        static AgreementUtilities()
		{
            AlgorithmOidMap[X9ObjectIdentifiers.DHSinglePassCofactorDHSha1KdfScheme] = "ECCDHWITHSHA1KDF";
            AlgorithmOidMap[X9ObjectIdentifiers.DHSinglePassStdDHSha1KdfScheme] = "ECDHWITHSHA1KDF";
            AlgorithmOidMap[X9ObjectIdentifiers.MqvSinglePassSha1KdfScheme] = "ECMQVWITHSHA1KDF";

            AlgorithmOidMap[EdECObjectIdentifiers.id_X25519] = "X25519";
            AlgorithmOidMap[EdECObjectIdentifiers.id_X448] = "X448";

#if DEBUG
            //foreach (var key in AlgorithmMap.Keys)
            //{
            //    if (DerObjectIdentifier.TryFromID(key, out var ignore))
            //        throw new Exception("OID mapping belongs in AlgorithmOidMap: " + key);
            //}

            //var mechanisms = new HashSet<string>(AlgorithmMap.Values);
            var mechanisms = new HashSet<string>();
            mechanisms.UnionWith(AlgorithmOidMap.Values);

            foreach (var mechanism in mechanisms)
            {
                //if (AlgorithmMap.TryGetValue(mechanism, out var check))
                //{
                //    if (mechanism != check)
                //        throw new Exception("Mechanism mapping MUST be to self: " + mechanism);
                //}
                //else
                {
                    if (!mechanism.Equals(mechanism.ToUpperInvariant()))
                        throw new Exception("Unmapped mechanism MUST be uppercase: " + mechanism);
                }
            }
#endif
        }

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);
        }

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
            if (mechanism == "DH" || mechanism == "DIFFIEHELLMAN")
				return new DHBasicAgreement();

			if (mechanism == "ECDH")
				return new ECDHBasicAgreement();

            if (mechanism == "ECDHC" || mechanism == "ECCDH")
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
            // 'DHWITHSHA1KDF' retained for backward compatibility
            if (mechanism == "DHWITHSHA1KDF" || mechanism == "ECDHWITHSHA1KDF")
                return new ECDHWithKdfBasicAgreement(wrapAlgorithm, new ECDHKekGenerator(new Sha1Digest()));

            if (mechanism == "ECCDHWITHSHA1KDF")
                return new ECDHCWithKdfBasicAgreement(wrapAlgorithm, new ECDHKekGenerator(new Sha1Digest()));

            if (mechanism == "ECMQVWITHSHA1KDF")
                return new ECMqvWithKdfBasicAgreement(wrapAlgorithm, new ECDHKekGenerator(new Sha1Digest()));

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

            return null;
        }

        private static string GetMechanism(string algorithm)
        {
            //if (AlgorithmMap.TryGetValue(algorithm, out var mechanism1))
            //    return mechanism1;

            if (DerObjectIdentifier.TryFromID(algorithm, out var oid))
            {
                if (AlgorithmOidMap.TryGetValue(oid, out var mechanism2))
                    return mechanism2;
            }

            return null;
        }
	}
}
