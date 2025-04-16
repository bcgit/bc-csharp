using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    public static class PqcUtilities
    {
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

        public static bool SupportsMLDsa(AlgorithmIdentifier pubKeyAlgID, DerObjectIdentifier mlDsaAlgOid)
        {
            return pubKeyAlgID.Algorithm.Equals(mlDsaAlgOid)
                && pubKeyAlgID.Parameters == null;
        }
    }
}
