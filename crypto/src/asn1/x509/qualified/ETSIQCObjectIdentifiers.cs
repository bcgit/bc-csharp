namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    // TODO[api] Make static
    public abstract class EtsiQCObjectIdentifiers
	{
        //
        // base id
        //
        public static readonly DerObjectIdentifier IdEtsiQcs = new DerObjectIdentifier("0.4.0.1862.1");

        public static readonly DerObjectIdentifier IdEtsiQcsQcCompliance = IdEtsiQcs.Branch("1");
        public static readonly DerObjectIdentifier IdEtsiQcsLimitValue = IdEtsiQcs.Branch("2");
        public static readonly DerObjectIdentifier IdEtsiQcsRetentionPeriod = IdEtsiQcs.Branch("3");
        public static readonly DerObjectIdentifier IdEtsiQcsQcSscd = IdEtsiQcs.Branch("4");
    }
}
