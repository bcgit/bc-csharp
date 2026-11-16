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
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.18</c>.</summary>
        public static readonly DerObjectIdentifier SignerAttr = PkcsObjectIdentifiers.IdAAEtsSignerAttr;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.19</c>.</summary>
        public static readonly DerObjectIdentifier OtherSigCert = PkcsObjectIdentifiers.IdAAEtsOtherSigCert;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.20</c>.</summary>
        public static readonly DerObjectIdentifier ContentTimestamp = PkcsObjectIdentifiers.IdAAEtsContentTimestamp;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.21</c>.</summary>
        public static readonly DerObjectIdentifier CertificateRefs = PkcsObjectIdentifiers.IdAAEtsCertificateRefs;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.22</c>.</summary>
        public static readonly DerObjectIdentifier RevocationRefs = PkcsObjectIdentifiers.IdAAEtsRevocationRefs;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.23</c>.</summary>
        public static readonly DerObjectIdentifier CertValues = PkcsObjectIdentifiers.IdAAEtsCertValues;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.24</c>.</summary>
        public static readonly DerObjectIdentifier RevocationValues = PkcsObjectIdentifiers.IdAAEtsRevocationValues;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.25</c>.</summary>
        public static readonly DerObjectIdentifier EscTimeStamp = PkcsObjectIdentifiers.IdAAEtsEscTimeStamp;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.26</c>.</summary>
        public static readonly DerObjectIdentifier CertCrlTimestamp = PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.27</c>.</summary>
        public static readonly DerObjectIdentifier ArchiveTimestamp = PkcsObjectIdentifiers.IdAAEtsArchiveTimestamp;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.48</c>.</summary>
        public static readonly DerObjectIdentifier ArchiveTimestampV2 = PkcsObjectIdentifiers.IdAAEtsArchiveTimestampV2;
    }
}
