using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for an ASN.1 OCTET STRING, giving access to its content as a stream.</summary>
    public interface Asn1OctetStringParser
        : IAsn1Convertible
    {
        /// <summary>Return the content of the OCTET STRING as a <see cref="Stream"/>.</summary>
        /// <returns>A <see cref="Stream"/> represnting the OCTET STRING's content.</returns>
        Stream GetOctetStream();
    }
}
