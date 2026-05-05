namespace Org.BouncyCastle.Asn1
{
    // TODO[asn1] Should be renamed/replaced with DLSequenceParser
    public class DerSequenceParser
        : Asn1SequenceParser
    {
        private readonly Asn1StreamParser m_parser;

        internal DerSequenceParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        public Asn1Object ToAsn1Object() => DLSequence.FromVector(m_parser.ReadVector());
    }
}
