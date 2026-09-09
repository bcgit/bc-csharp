using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Utilities
{
    internal static class GostUtilities
    {
        /// <summary>
        /// Create the key <see cref="AlgorithmIdentifier"/> under which an ECGOST3410 key should be encoded (e.g. in
        /// a SubjectPublicKeyInfo or PrivateKeyInfo).
        /// </summary>
        /// <remarks>
        /// GOST R 34.10-2001 keys (RFC 4491, Section 2.3.2) carry a GOST R 34.11-94 digestParamSet, whereas GOST R
        /// 34.10-2012 keys (RFC 9215, Section 4.2) carry a GOST R 34.11-2012 digestParamSet or omit it. RFC 9215 also
        /// permits the legacy GOST R 34.10-2001 parameter sets to be used as the publicKeyParamSet of a GOST R
        /// 34.10-2012 key, so the digest parameter set (not the curve) is the discriminator between 2001 and 2012.
        /// </remarks>
        /// <exception cref="ArgumentException">If the digest parameter set is not recognized.</exception>
        internal static AlgorithmIdentifier CreateECGost3410AlgorithmIdentifier(ECGost3410Parameters parameters)
        {
            var algOid = GetECGost3410KeyAlgorithmOid(parameters);
            var algParams = new Gost3410PublicKeyAlgParameters(parameters.PublicKeyParamSet,
                parameters.DigestParamSet, parameters.EncryptionParamSet);
            return new AlgorithmIdentifier(algOid, algParams);
        }

        private static DerObjectIdentifier GetECGost3410KeyAlgorithmOid(ECGost3410Parameters parameters)
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
    }
}
