namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for an ASN.1 SEQUENCE that returns its elements one at a time.</summary>
    public interface Asn1SequenceParser
        : IAsn1Convertible
    {
        IAsn1Convertible ReadObject();
    }
}
