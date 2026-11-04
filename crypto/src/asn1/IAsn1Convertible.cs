namespace Org.BouncyCastle.Asn1
{
    /// <summary>Implemented by objects that can be converted to an ASN.1 object.</summary>
    // TODO[api] Make generic on the return type of ToAsn1Object()
    // TODO[api] Have a different interface that is only for custom ASN.1 types
    public interface IAsn1Convertible
    {
        /// <summary>Convert this object to an ASN.1 object.</summary>
        /// <returns>The ASN.1 object.</returns>
        Asn1Object ToAsn1Object();
    }
}
