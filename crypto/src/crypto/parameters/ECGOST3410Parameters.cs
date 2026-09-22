using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X9;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECGost3410Parameters
        : ECNamedDomainParameters
    {
        public static ECGost3410Parameters FromPublicKeyParameters(
            GostR3410x2001PublicKeyParameters publicKeyParameters)
        {
            if (publicKeyParameters == null)
                throw new ArgumentNullException(nameof(publicKeyParameters));

            return new ECGost3410Parameters(publicKeyParameters.PublicKeyParamSet,
                publicKeyParameters.DigestParamSet, publicKeyParameters.EncryptionParamSet);
        }

        public static ECGost3410Parameters FromPublicKeyParameters(
            GostR3410x2012PublicKeyParameters publicKeyParameters)
        {
            if (publicKeyParameters == null)
                throw new ArgumentNullException(nameof(publicKeyParameters));

            return new ECGost3410Parameters(publicKeyParameters.PublicKeyParamSet,
                publicKeyParameters.DigestParamSet, encryptionParamSet: null);
        }

        private readonly DerObjectIdentifier m_digestParamSet;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        public ECGost3410Parameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet,
            DerObjectIdentifier encryptionParamSet)
            : this(GetX9ECParameters(publicKeyParamSet), publicKeyParamSet, digestParamSet, encryptionParamSet)
        {
        }

        private ECGost3410Parameters(X9ECParameters x9ECParameters, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
            : base(publicKeyParamSet, x9ECParameters)
        {
            // Invalid for both structures: GOST R 34.10-2001 requires digestParamSet and GOST R 34.10-2012 has no
            // encryptionParamSet (see Gost3410PublicKeyAlgParameters).
            if (digestParamSet == null && encryptionParamSet != null)
                throw new ArgumentException("encryptionParamSet requires digestParamSet", nameof(encryptionParamSet));

            m_digestParamSet = digestParamSet;
            m_encryptionParamSet = encryptionParamSet;
        }

        [Obsolete("Use 'FromPublicKeyParameters' or param-sets-only constructor instead")]
        public ECGost3410Parameters(ECNamedDomainParameters dp, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
            : this(ValidateDomainParameters(dp, publicKeyParamSet), publicKeyParamSet, digestParamSet,
                encryptionParamSet)
        {
        }

        [Obsolete("Use 'FromPublicKeyParameters' or param-sets-only constructor instead")]
        public ECGost3410Parameters(ECDomainParameters dp, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
            : this(ValidateDomainParameters(dp, publicKeyParamSet), publicKeyParamSet, digestParamSet,
                encryptionParamSet)
        {
        }

        public DerObjectIdentifier PublicKeyParamSet => Name;

        public DerObjectIdentifier DigestParamSet => m_digestParamSet;

        public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;

        private static X9ECParameters GetX9ECParameters(DerObjectIdentifier publicKeyParamSet)
        {
            return ECGost3410NamedCurves.GetByOid(publicKeyParamSet)
                ?? throw new ArgumentException("Unrecognized ECGOST3410 curve OID", nameof(publicKeyParamSet));
        }

        /// <summary>
        /// Check that <paramref name="dp"/> is consistent with the ECGOST3410 named curve identified by
        /// <paramref name="publicKeyParamSet"/>, and return that curve (from which the instance is then built).
        /// </summary>
        private static X9ECParameters ValidateDomainParameters(ECDomainParameters dp,
            DerObjectIdentifier publicKeyParamSet)
        {
            if (dp == null)
                throw new ArgumentNullException(nameof(dp));
            if (publicKeyParamSet == null)
                throw new ArgumentNullException(nameof(publicKeyParamSet));

            var x962Parameters = dp.ToX962Parameters();
            if (x962Parameters.IsNamedCurve && !publicKeyParamSet.Equals(x962Parameters.NamedCurve))
            {
                throw new ArgumentException("Curve name does not match the specified 'publicKeyParamSet'",
                    nameof(dp));
            }

            var x9ECParameters = GetX9ECParameters(publicKeyParamSet);

            if (!FromX9ECParameters(x9ECParameters).Equals(dp))
            {
                throw new ArgumentException("Domain parameters do not match the specified 'publicKeyParamSet'",
                    nameof(dp));
            }

            return x9ECParameters;
        }
    }
}
