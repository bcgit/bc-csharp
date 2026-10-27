using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for a BER encoded SET.</summary>
    [Obsolete("Check for 'Asn1SetParser' instead")]
    public class BerSetParser
        : Asn1SetParser
    {
        private readonly Asn1StreamParser m_parser;

        internal BerSetParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        /// <inheritdoc/>
        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        /// <inheritdoc/>
        public Asn1Object ToAsn1Object() => Parse(m_parser);

        internal static BerSet Parse(Asn1StreamParser sp) => BerSet.FromVector(sp.ReadVector());
    }
}
