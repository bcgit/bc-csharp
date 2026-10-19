namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for an ASN.1 SET that returns its elements one at a time.</summary>
    public interface Asn1SetParser
        : IAsn1Convertible
    {
        /// <summary>Read the next object from the set.</summary>
        /// <returns>The next object, or null if the end of the set has been reached.</returns>
        IAsn1Convertible ReadObject();
    }
}
