using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>
    /// Utility methods relating post-quantum signature schemes to their parameters and object identifiers.
    /// </summary>
    public static class PqcUtilities
    {
        /// <summary>Get the object identifier of the ML-DSA parameter set for a signature scheme.</summary>
        /// <param name="signatureScheme">The signature scheme.</param>
        /// <returns>The object identifier.</returns>
        /// <exception cref="ArgumentException">The signature scheme is not an ML-DSA scheme.</exception>
        public static DerObjectIdentifier GetMLDsaObjectidentifier(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case SignatureScheme.mldsa44:
                return NistObjectIdentifiers.id_ml_dsa_44;
            case SignatureScheme.mldsa65:
                return NistObjectIdentifiers.id_ml_dsa_65;
            case SignatureScheme.mldsa87:
                return NistObjectIdentifiers.id_ml_dsa_87;
            default:
                throw new ArgumentException();
            }
        }

        /// <summary>Get the signature scheme for an ML-DSA parameter set.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The signature scheme.</returns>
        /// <exception cref="ArgumentException">The parameters have no corresponding signature scheme.</exception>
        public static int GetMLDsaSignatureScheme(MLDsaParameters parameters)
        {
            if (MLDsaParameters.ml_dsa_44 == parameters)
                return SignatureScheme.mldsa44;
            if (MLDsaParameters.ml_dsa_65 == parameters)
                return SignatureScheme.mldsa65;
            if (MLDsaParameters.ml_dsa_87 == parameters)
                return SignatureScheme.mldsa87;
            throw new ArgumentException();
        }

        /// <summary>Get the object identifier of the SLH-DSA parameter set for a signature scheme.</summary>
        /// <param name="signatureScheme">The signature scheme.</param>
        /// <returns>The object identifier.</returns>
        /// <exception cref="ArgumentException">The signature scheme is not an SLH-DSA scheme.</exception>
        public static DerObjectIdentifier GetSlhDsaObjectidentifier(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case SignatureScheme.slhdsa_sha2_128s:
                return NistObjectIdentifiers.id_slh_dsa_sha2_128s;
            case SignatureScheme.slhdsa_sha2_128f:
                return NistObjectIdentifiers.id_slh_dsa_sha2_128f;
            case SignatureScheme.slhdsa_sha2_192s:
                return NistObjectIdentifiers.id_slh_dsa_sha2_192s;
            case SignatureScheme.slhdsa_sha2_192f:
                return NistObjectIdentifiers.id_slh_dsa_sha2_192f;
            case SignatureScheme.slhdsa_sha2_256s:
                return NistObjectIdentifiers.id_slh_dsa_sha2_256s;
            case SignatureScheme.slhdsa_sha2_256f:
                return NistObjectIdentifiers.id_slh_dsa_sha2_256f;
            case SignatureScheme.slhdsa_shake_128s:
                return NistObjectIdentifiers.id_slh_dsa_shake_128s;
            case SignatureScheme.slhdsa_shake_128f:
                return NistObjectIdentifiers.id_slh_dsa_shake_128f;
            case SignatureScheme.slhdsa_shake_192s:
                return NistObjectIdentifiers.id_slh_dsa_shake_192s;
            case SignatureScheme.slhdsa_shake_192f:
                return NistObjectIdentifiers.id_slh_dsa_shake_192f;
            case SignatureScheme.slhdsa_shake_256s:
                return NistObjectIdentifiers.id_slh_dsa_shake_256s;
            case SignatureScheme.slhdsa_shake_256f:
                return NistObjectIdentifiers.id_slh_dsa_shake_256f;
            default:
                throw new ArgumentException();
            }
        }

        /// <summary>Get the signature scheme for an SLH-DSA parameter set.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The signature scheme.</returns>
        /// <exception cref="ArgumentException">The parameters have no corresponding signature scheme.</exception>
        public static int GetSlhDsaSignatureScheme(SlhDsaParameters parameters)
        {
            if (SlhDsaParameters.slh_dsa_sha2_128s == parameters)
                return SignatureScheme.slhdsa_sha2_128s;
            if (SlhDsaParameters.slh_dsa_sha2_128f == parameters)
                return SignatureScheme.slhdsa_sha2_128f;
            if (SlhDsaParameters.slh_dsa_sha2_192s == parameters)
                return SignatureScheme.slhdsa_sha2_192s;
            if (SlhDsaParameters.slh_dsa_sha2_192f == parameters)
                return SignatureScheme.slhdsa_sha2_192f;
            if (SlhDsaParameters.slh_dsa_sha2_256s == parameters)
                return SignatureScheme.slhdsa_sha2_256s;
            if (SlhDsaParameters.slh_dsa_sha2_256f == parameters)
                return SignatureScheme.slhdsa_sha2_256f;
            if (SlhDsaParameters.slh_dsa_shake_128s == parameters)
                return SignatureScheme.slhdsa_shake_128s;
            if (SlhDsaParameters.slh_dsa_shake_128f == parameters)
                return SignatureScheme.slhdsa_shake_128f;
            if (SlhDsaParameters.slh_dsa_shake_192s == parameters)
                return SignatureScheme.slhdsa_shake_192s;
            if (SlhDsaParameters.slh_dsa_shake_192f == parameters)
                return SignatureScheme.slhdsa_shake_192f;
            if (SlhDsaParameters.slh_dsa_shake_256s == parameters)
                return SignatureScheme.slhdsa_shake_256s;
            if (SlhDsaParameters.slh_dsa_shake_256f == parameters)
                return SignatureScheme.slhdsa_shake_256f;
            throw new ArgumentException();
        }

        /// <summary>Determine whether a public key algorithm can be used with a given ML-DSA algorithm.</summary>
        /// <param name="pubKeyAlgID">The public key algorithm identifier.</param>
        /// <param name="mlDsaAlgOid">The ML-DSA algorithm object identifier.</param>
        /// <returns>true if it is supported, false otherwise.</returns>
        public static bool SupportsMLDsa(AlgorithmIdentifier pubKeyAlgID, DerObjectIdentifier mlDsaAlgOid) =>
            HasOidWithNullParameters(pubKeyAlgID, mlDsaAlgOid);

        /// <summary>Determine whether a public key algorithm can be used with a given SLH-DSA algorithm.</summary>
        /// <param name="pubKeyAlgID">The public key algorithm identifier.</param>
        /// <param name="slhDsaAlgOid">The SLH-DSA algorithm object identifier.</param>
        /// <returns>true if it is supported, false otherwise.</returns>
        public static bool SupportsSlhDsa(AlgorithmIdentifier pubKeyAlgID, DerObjectIdentifier slhDsaAlgOid) =>
            HasOidWithNullParameters(pubKeyAlgID, slhDsaAlgOid);

        private static bool HasOidWithNullParameters(AlgorithmIdentifier algID, DerObjectIdentifier algOid) =>
            algID.Algorithm.Equals(algOid) && algID.Parameters == null;
    }
}
