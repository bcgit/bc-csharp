namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for an ASN.1 SET that returns its elements one at a time.</summary>
    public interface Asn1SetParser
        : IAsn1Convertible
    {
        IAsn1Convertible ReadObject();
    }
}
