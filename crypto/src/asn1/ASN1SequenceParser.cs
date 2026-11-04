namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for an ASN.1 SEQUENCE that returns its elements one at a time.</summary>
    public interface Asn1SequenceParser
        : IAsn1Convertible
    {
        /// <summary>Read the next object from the sequence.</summary>
        /// <returns>The next object, or null if the end of the sequence has been reached.</returns>
        IAsn1Convertible ReadObject();
    }
}
