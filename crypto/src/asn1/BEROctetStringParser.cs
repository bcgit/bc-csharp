using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for a BER encoded OCTET STRING.</summary>
    [Obsolete("Check for 'Asn1OctetStringParser' instead")]
    public class BerOctetStringParser
        : Asn1OctetStringParser
    {
        private readonly Asn1StreamParser m_parser;

        internal BerOctetStringParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        /// <inheritdoc/>
        public Stream GetOctetStream() => new ConstructedOctetStream(m_parser);

        /// <inheritdoc/>
        public Asn1Object ToAsn1Object()
        {
            try
            {
                return Parse(m_parser);
            }
            catch (IOException e)
            {
                throw new Asn1ParsingException("IOException converting stream to byte array", e);
            }
        }

        internal static BerOctetString Parse(Asn1StreamParser sp) =>
            new BerOctetString(Streams.ReadAll(new ConstructedOctetStream(sp)));
    }
}
