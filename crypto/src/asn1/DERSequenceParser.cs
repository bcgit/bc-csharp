namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for a DER encoded SEQUENCE.</summary>
    // TODO[asn1] Should be renamed/replaced with DLSequenceParser
    public class DerSequenceParser
        : Asn1SequenceParser
    {
        private readonly Asn1StreamParser m_parser;

        internal DerSequenceParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        /// <inheritdoc/>
        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        /// <inheritdoc/>
        public Asn1Object ToAsn1Object() => DLSequence.FromVector(m_parser.ReadVector());
    }
}
