using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for a DER encoded OCTET STRING.</summary>
    public class DerOctetStringParser
        : Asn1OctetStringParser
    {
        private readonly DefiniteLengthInputStream m_stream;

        internal DerOctetStringParser(DefiniteLengthInputStream stream)
        {
            m_stream = stream;
        }

        /// <inheritdoc/>
        public Stream GetOctetStream() => m_stream;

        /// <inheritdoc/>
        public Asn1Object ToAsn1Object()
        {
            try
            {
                return DerOctetString.WithContents(m_stream.ToArray());
            }
            catch (IOException e)
            {
                throw new Asn1ParsingException("IOException converting stream to byte array", e);
            }
        }
    }
}
