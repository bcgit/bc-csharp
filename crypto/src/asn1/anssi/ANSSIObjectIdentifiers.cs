namespace Org.BouncyCastle.Asn1.Anssi
{
    /// <summary>Object identifiers for ANSSI, the French national cybersecurity agency.</summary>
    // TODO[api] Make static
    public sealed class AnssiObjectIdentifiers
    {
        private AnssiObjectIdentifiers()
        {
        }

        /// <summary>The object identifier <c>1.2.250.1.223.101.256.1</c>.</summary>
        public static readonly DerObjectIdentifier FRP256v1 = new DerObjectIdentifier("1.2.250.1.223.101.256.1");
    }
}
