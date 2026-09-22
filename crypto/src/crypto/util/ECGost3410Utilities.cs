using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Utilities
{
    internal static class ECGost3410Utilities
    {
        /// <summary>
        /// Whether <paramref name="algOid"/> is a key algorithm OID for ECGOST3410 keys (as found in a
        /// SubjectPublicKeyInfo or PrivateKeyInfo).
        /// </summary>
        /// <remarks>
        /// The GOST R 34.10-2012 agreement OIDs are accepted here, but <see cref="CreateAlgorithmIdentifier"/> only
        /// ever encodes ECGOST3410 keys under the signature OIDs, so a key decoded from an agreement OID will
        /// re-encode under the corresponding signature OID.
        /// </remarks>
        internal static bool IsKeyAlgorithmOid(DerObjectIdentifier algOid)
        {
            return CryptoProObjectIdentifiers.GostR3410x2001.Equals(algOid)
                || RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Equals(algOid)
                || RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Equals(algOid)
                || RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.Equals(algOid)
                || RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512.Equals(algOid);
        }

        /// <summary>
        /// Recover the <see cref="ECGost3410Parameters"/> from the key <see cref="AlgorithmIdentifier"/> of an
        /// ECGOST3410 key (the inverse of <see cref="CreateAlgorithmIdentifier"/>).
        /// </summary>
        /// <remarks>
        /// The parameters are normally a <see cref="GostR3410x2001PublicKeyParameters"/> or
        /// <see cref="GostR3410x2012PublicKeyParameters"/> SEQUENCE, according to the key algorithm; for GOST R
        /// 34.10-2001 an absent encryptionParamSet is reported as its DEFAULT. A bare curve OID (as written e.g. by the
        /// bc-java provider) is also accepted; it carries no digestParamSet, so defaults are derived from the key
        /// algorithm and the curve (see <see cref="CreateDefaultParameters"/>). Explicit EC parameters are rejected.
        /// <para/>
        /// bc-csharp versions prior to 2.8.0 could write an encryptionParamSet for GOST R 34.10-2012 keys, which the
        /// RFC 9215 structure does not have, or a TC26 parameter set under the GOST R 34.10-2001 key algorithm, which
        /// RFC 4491 does not allow; both are rejected unless
        /// <see cref="Properties.GostAllowLenientKeyParameters"/> is set.
        /// </remarks>
        /// <exception cref="ArgumentException">If the algorithm identifier is not that of an ECGOST3410 key, or its
        /// parameters are missing or invalid.</exception>
        internal static ECGost3410Parameters ParseAlgorithmIdentifier(AlgorithmIdentifier algID)
        {
            DerObjectIdentifier algOid = algID.Algorithm;
            if (!IsKeyAlgorithmOid(algOid))
                throw new ArgumentException("Not an ECGOST3410 key algorithm: " + algOid, nameof(algID));

            Asn1Object p = algID.Parameters?.ToAsn1Object()
                ?? throw new ArgumentException("Missing algorithm parameters for ECGOST3410 key", nameof(algID));

            bool gost2012PerAlg = !CryptoProObjectIdentifiers.GostR3410x2001.Equals(algOid);

            if (p is Asn1Sequence seq && seq.Count >= 1 && seq.Count <= 3)
            {
                if (gost2012PerAlg)
                    return ParseGost2012Parameters(seq);

                var gost2001Params = GostR3410x2001PublicKeyParameters.GetInstance(seq);
                CheckGost2001ParamSet(gost2001Params.PublicKeyParamSet, nameof(algID));
                return ECGost3410Parameters.FromPublicKeyParameters(gost2001Params);
            }

            var x962Parameters = X962Parameters.GetInstance(p);
            if (!x962Parameters.IsNamedCurve)
                throw new ArgumentException("Explicit EC parameters invalid for ECGOST3410 key", nameof(algID));

            var namedCurve = x962Parameters.NamedCurve;
            if (!gost2012PerAlg)
            {
                CheckGost2001ParamSet(namedCurve, nameof(algID));
            }

            return CreateDefaultParameters(isGost2012: gost2012PerAlg, namedCurve);
        }

        /// <summary>
        /// GOST R 34.10-2001 (RFC 4491) defines no TC26 parameter sets, so reject one under the GOST R 34.10-2001 key
        /// algorithm (unless <see cref="Properties.GostAllowLenientKeyParameters"/> is set).
        /// </summary>
        private static void CheckGost2001ParamSet(DerObjectIdentifier publicKeyParamSet, string paramName)
        {
            if (IsTc26ParamSet(publicKeyParamSet) &&
                !Properties.GetBoolean(Properties.GostAllowLenientKeyParameters, false))
            {
                throw new ArgumentException("TC26 parameter set invalid for GOST R 34.10-2001 key", paramName);
            }
        }

        private static ECGost3410Parameters ParseGost2012Parameters(Asn1Sequence seq)
        {
            if (seq.Count > 2 && Properties.GetBoolean(Properties.GostAllowLenientKeyParameters, false))
            {
                var legacyParams = Gost3410PublicKeyAlgParameters.GetInstance(seq);
                return new ECGost3410Parameters(legacyParams.PublicKeyParamSet, legacyParams.DigestParamSet,
                    legacyParams.EncryptionParamSet);
            }

            return ECGost3410Parameters.FromPublicKeyParameters(GostR3410x2012PublicKeyParameters.GetInstance(seq));
        }

        /// <summary>
        /// Create the key <see cref="AlgorithmIdentifier"/> under which an ECGOST3410 key should be encoded (e.g. in
        /// a SubjectPublicKeyInfo or PrivateKeyInfo).
        /// </summary>
        /// <remarks>
        /// GOST R 34.10-2001 keys (RFC 4491, Section 2.3.2) carry a GOST R 34.11-94 digestParamSet, whereas GOST R
        /// 34.10-2012 keys (RFC 9215, Section 4.2) carry a GOST R 34.11-2012 digestParamSet or omit it. RFC 9215 also
        /// permits the legacy GOST R 34.10-2001 parameter sets to be used as the publicKeyParamSet of a GOST R
        /// 34.10-2012 key, so the digest parameter set (not the curve) is the discriminator between 2001 and 2012.
        /// <para/>
        /// The GOST R 34.10-2012 structure has no encryptionParamSet, so any such value is not encoded for those keys
        /// (nothing in the library makes use of it).
        /// </remarks>
        /// <exception cref="ArgumentException">If the digest parameter set is not recognized.</exception>
        internal static AlgorithmIdentifier CreateAlgorithmIdentifier(ECGost3410Parameters parameters)
        {
            var algOid = GetKeyAlgorithmOid(parameters);

            Asn1Encodable algParams;
            if (CryptoProObjectIdentifiers.GostR3410x2001.Equals(algOid))
            {
                algParams = new GostR3410x2001PublicKeyParameters(parameters.PublicKeyParamSet,
                    parameters.DigestParamSet, parameters.EncryptionParamSet);
            }
            else
            {
                algParams = new GostR3410x2012PublicKeyParameters(parameters.PublicKeyParamSet,
                    parameters.DigestParamSet);
            }

            return new AlgorithmIdentifier(algOid, algParams);
        }

        /// <summary>
        /// Determine the key algorithm OID (GOST R 34.10-2001, or GOST R 34.10-2012 with 256- or 512-bit keys) for an
        /// ECGOST3410 key. See <see cref="CreateAlgorithmIdentifier"/> for the rules.
        /// </summary>
        /// <exception cref="ArgumentException">If the digest parameter set is not recognized.</exception>
        internal static DerObjectIdentifier GetKeyAlgorithmOid(ECGost3410Parameters parameters)
        {
            DerObjectIdentifier digestParamSet = parameters.DigestParamSet;

            if (digestParamSet == null ||
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Equals(digestParamSet) ||
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Equals(digestParamSet))
            {
                return parameters.Curve.FieldElementEncodingLength > 32
                    ? RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512
                    : RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
            }

            if (CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet.Equals(digestParamSet) ||
                CryptoProObjectIdentifiers.GostR3411x94TestParamSet.Equals(digestParamSet))
            {
                return CryptoProObjectIdentifiers.GostR3410x2001;
            }

            throw new ArgumentException("Unrecognized GOST R 34.11 digestParamSet: " + digestParamSet,
                nameof(parameters));
        }

        /// <summary>
        /// The size in octets of a field element(and so of each coordinate and of the private key) for the key's curve:
        /// 32 for the 256-bit parameter sets, 64 for the 512-bit ones.
        /// </summary>
        internal static int GetFieldElementEncodingLength(ECGost3410Parameters parameters) =>
            parameters.Curve.FieldElementEncodingLength;

        /// <summary>
        /// Whether an EC key algorithm name (as canonicalized by <see cref="ECKeyParameters"/>) denotes an ECGOST3410
        /// key.
        /// </summary>
        /// <param name="algorithm">The algorithm name.</param>
        /// <param name="gost2012PerName">Whether the name specifically denotes GOST R 34.10-2012.</param>
        internal static bool IsGostAlgorithmName(string algorithm, out bool gost2012PerName)
        {
            gost2012PerName = algorithm == "ECGOST3410-2012";
            return gost2012PerName || algorithm == "ECGOST3410";
        }

        /// <summary>
        /// Get the <see cref="ECGost3410Parameters"/> under which an EC key should be encoded, or null if the key is
        /// not an ECGOST3410 key.
        /// </summary>
        /// <remarks>
        /// A key constructed directly with an "ECGOST3410" or "ECGOST3410-2012" algorithm name may carry plain
        /// <see cref="ECNamedDomainParameters"/>; such a key is promoted here (see
        /// <see cref="TryGetECGost3410Parameters"/>).
        /// </remarks>
        /// <exception cref="ArgumentException">If an ECGOST3410 key does not have the domain parameters of a named
        /// ECGOST3410 parameter set.</exception>
        internal static ECGost3410Parameters GetEncodingParameters(ECKeyParameters ecKey)
        {
            if (ecKey.Parameters is ECGost3410Parameters gostParameters)
                return gostParameters;

            if (!IsGostAlgorithmName(ecKey.AlgorithmName, out bool gost2012PerName))
                return null;

            if (!TryGetECGost3410Parameters(gost2012PerName, ecKey.Parameters, out var ecGost3410Parameters))
            {
                throw new ArgumentException(
                    "ECGOST3410 keys require the domain parameters of a named ECGOST3410 parameter set", nameof(ecKey));
            }

            return ecGost3410Parameters;
        }

        /// <summary>
        /// Get the domain parameters of an ECGOST3410 key as <see cref="ECGost3410Parameters"/>, promoting them if
        /// necessary; fails if they are not those of a named ECGOST3410 parameter set.
        /// </summary>
        /// <remarks>
        /// Plain <see cref="ECNamedDomainParameters"/> (e.g. from
        /// <see cref="ECKeyGenerationParameters(DerObjectIdentifier, Security.SecureRandom)"/>) are promoted using
        /// <see cref="CreateDefaultParameters"/>. A TC26 parameter set is always treated as GOST R 34.10-2012,
        /// whatever <paramref name="gost2012PerName"/> says, since GOST R 34.10-2001 (RFC 4491) defines no such
        /// curves.
        /// </remarks>
        /// <param name="gost2012PerName">Whether the key's algorithm name specifically denotes GOST R 34.10-2012
        /// (see <see cref="IsGostAlgorithmName"/>).</param>
        /// <param name="domainParameters">The key's domain parameters.</param>
        /// <param name="ecGost3410Parameters">The resulting parameters, or null on failure.</param>
        internal static bool TryGetECGost3410Parameters(bool gost2012PerName, ECDomainParameters domainParameters,
            out ECGost3410Parameters ecGost3410Parameters)
        {
            if (domainParameters is ECGost3410Parameters gostParameters)
            {
                ecGost3410Parameters = gostParameters;
                return true;
            }

            ecGost3410Parameters = null;

            var publicKeyParamSet = (domainParameters as ECNamedDomainParameters)?.Name;
            if (publicKeyParamSet == null || ECGost3410NamedCurves.GetByOid(publicKeyParamSet) == null)
                return false;

            bool gost2012PerCurve = IsTc26ParamSet(publicKeyParamSet);
            bool isGost2012 = gost2012PerName || gost2012PerCurve;

            var promoted = CreateDefaultParameters(isGost2012, publicKeyParamSet);

            // The name alone selects the curve, so it must agree with the domain parameters
            if (!promoted.Equals(domainParameters))
                return false;

            ecGost3410Parameters = promoted;
            return true;
        }

        /// <summary>
        /// Create the <see cref="ECGost3410Parameters"/> for an ECGOST3410 key identified only by its curve, with the
        /// default digestParamSet (see <see cref="GetDefaultDigestParamSet"/>) and, for GOST R 34.10-2001, the DEFAULT
        /// encryptionParamSet.
        /// </summary>
        private static ECGost3410Parameters CreateDefaultParameters(bool isGost2012,
            DerObjectIdentifier publicKeyParamSet)
        {
            var digestParamSet = GetDefaultDigestParamSet(isGost2012, publicKeyParamSet);
            var encryptionParamSet = isGost2012 ? null : GostR3410x2001PublicKeyParameters.DefaultEncryptionParamSet;

            return new ECGost3410Parameters(publicKeyParamSet, digestParamSet, encryptionParamSet);
        }

        /// <summary>
        /// The digestParamSet to use for an ECGOST3410 key when none was specified.
        /// </summary>
        /// <remarks>
        /// GOST R 34.10-2001 keys carry a GOST R 34.11-94 parameter set (RFC 4491, Section 2.3.2). For GOST R
        /// 34.10-2012 keys, RFC 9215 (Section 4.2) requires id-tc26-gost3411-12-256 with the legacy GOST R 34.10-2001
        /// parameter sets, and requires or recommends omitting the digestParamSet with the TC26 parameter sets.
        /// </remarks>
        private static DerObjectIdentifier GetDefaultDigestParamSet(bool isGost2012,
            DerObjectIdentifier publicKeyParamSet)
        {
            if (!isGost2012)
                return CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;

            return IsTc26ParamSet(publicKeyParamSet) ? null : RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
        }

        private static bool IsTc26ParamSet(DerObjectIdentifier publicKeyParamSet) =>
            publicKeyParamSet.On(RosstandartObjectIdentifiers.id_tc26);
    }
}
