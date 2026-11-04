using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <summary>Object identifiers for the commitment types of ETSI TS 101 733.</summary>
    // TODO[api] Make static
    public abstract class CommitmentTypeIdentifier
    {
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.1</c>.</summary>
        public static readonly DerObjectIdentifier ProofOfOrigin = PkcsObjectIdentifiers.IdCtiEtsProofOfOrigin;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.2</c>.</summary>
        public static readonly DerObjectIdentifier ProofOfReceipt = PkcsObjectIdentifiers.IdCtiEtsProofOfReceipt;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.3</c>.</summary>
        public static readonly DerObjectIdentifier ProofOfDelivery = PkcsObjectIdentifiers.IdCtiEtsProofOfDelivery;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.4</c>.</summary>
        public static readonly DerObjectIdentifier ProofOfSender = PkcsObjectIdentifiers.IdCtiEtsProofOfSender;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.5</c>.</summary>
        public static readonly DerObjectIdentifier ProofOfApproval = PkcsObjectIdentifiers.IdCtiEtsProofOfApproval;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.6.6</c>.</summary>
        public static readonly DerObjectIdentifier ProofOfCreation = PkcsObjectIdentifiers.IdCtiEtsProofOfCreation;
    }
}
