namespace Org.BouncyCastle.Asn1.Kisa
{
    /// <summary>Object identifiers for KISA, the Korea Internet and Security Agency.</summary>
    // TODO[api] Make static
    public abstract class KisaObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.2.410.200004.1.4</c>.</summary>
        public static readonly DerObjectIdentifier IdSeedCbc = new DerObjectIdentifier("1.2.410.200004.1.4");
        /// <summary>The object identifier <c>1.2.410.200004.7.1.1.1</c>.</summary>
        public static readonly DerObjectIdentifier IdNpkiAppCmsSeedWrap = new DerObjectIdentifier("1.2.410.200004.7.1.1.1");
    }
}
