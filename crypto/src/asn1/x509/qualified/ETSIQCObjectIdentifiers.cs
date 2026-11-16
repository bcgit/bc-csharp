namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /// <summary>Object identifiers for the ETSI qualified certificate statements.</summary>
    // TODO[api] Make static
    public abstract class EtsiQCObjectIdentifiers
    {
        /// <summary>The object identifier <c>0.4.0.1862.1</c>.</summary>
        //
        // base id
        //
        public static readonly DerObjectIdentifier IdEtsiQcs = new DerObjectIdentifier("0.4.0.1862.1");

        /// <summary>The object identifier <c>0.4.0.1862.1.1</c>.</summary>
        public static readonly DerObjectIdentifier IdEtsiQcsQcCompliance = IdEtsiQcs.Branch("1");
        /// <summary>The object identifier <c>0.4.0.1862.1.2</c>.</summary>
        public static readonly DerObjectIdentifier IdEtsiQcsLimitValue = IdEtsiQcs.Branch("2");
        /// <summary>The object identifier <c>0.4.0.1862.1.3</c>.</summary>
        public static readonly DerObjectIdentifier IdEtsiQcsRetentionPeriod = IdEtsiQcs.Branch("3");
        /// <summary>The object identifier <c>0.4.0.1862.1.4</c>.</summary>
        public static readonly DerObjectIdentifier IdEtsiQcsQcSscd = IdEtsiQcs.Branch("4");
        /// <summary>The object identifier <c>0.4.0.1862.1.7</c>.</summary>
        public static readonly DerObjectIdentifier IdEtsiQcsQcCClegislation = IdEtsiQcs.Branch("7");
    }
}
