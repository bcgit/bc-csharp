using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <summary>The object identifiers of the ETSI electronic signature format attributes.</summary>
    // TODO[api] Make static
    public abstract class EsfAttributes
    {
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.15</c>.</summary>
        public static readonly DerObjectIdentifier SigPolicyId = PkcsObjectIdentifiers.IdAAEtsSigPolicyID;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.16</c>.</summary>
        public static readonly DerObjectIdentifier CommitmentType = PkcsObjectIdentifiers.IdAAEtsCommitmentType;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.17</c>.</summary>
        public static readonly DerObjectIdentifier SignerLocation = PkcsObjectIdentifiers.IdAAEtsSignerLocation;
        public static readonly DerObjectIdentifier SignerAttr = PkcsObjectIdentifiers.IdAAEtsSignerAttr;
        public static readonly DerObjectIdentifier OtherSigCert = PkcsObjectIdentifiers.IdAAEtsOtherSigCert;
        public static readonly DerObjectIdentifier ContentTimestamp = PkcsObjectIdentifiers.IdAAEtsContentTimestamp;
        public static readonly DerObjectIdentifier CertificateRefs = PkcsObjectIdentifiers.IdAAEtsCertificateRefs;
        public static readonly DerObjectIdentifier RevocationRefs = PkcsObjectIdentifiers.IdAAEtsRevocationRefs;
        public static readonly DerObjectIdentifier CertValues = PkcsObjectIdentifiers.IdAAEtsCertValues;
        public static readonly DerObjectIdentifier RevocationValues = PkcsObjectIdentifiers.IdAAEtsRevocationValues;
        public static readonly DerObjectIdentifier EscTimeStamp = PkcsObjectIdentifiers.IdAAEtsEscTimeStamp;
        public static readonly DerObjectIdentifier CertCrlTimestamp = PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp;
        public static readonly DerObjectIdentifier ArchiveTimestamp = PkcsObjectIdentifiers.IdAAEtsArchiveTimestamp;
        public static readonly DerObjectIdentifier ArchiveTimestampV2 = PkcsObjectIdentifiers.IdAAEtsArchiveTimestampV2;
    }
}
