using System;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Check for 'Asn1SequenceParser' instead")]
    public class BerSequenceParser
        : Asn1SequenceParser
    {
        private readonly Asn1StreamParser m_parser;

        internal BerSequenceParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        public Asn1Object ToAsn1Object() => Parse(m_parser);

        internal static BerSequence Parse(Asn1StreamParser sp) => BerSequence.FromVector(sp.ReadVector());
    }
}
