namespace Org.BouncyCastle.Asn1
{
    /// <summary>Parser for a DER encoded SET.</summary>
    // TODO[asn1] Should be renamed/replaced with DLSetParser
    public class DerSetParser
        : Asn1SetParser
    {
        private readonly Asn1StreamParser m_parser;

        internal DerSetParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        /// <inheritdoc/>
        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        /// <inheritdoc/>
        public Asn1Object ToAsn1Object() => DLSet.FromVector(m_parser.ReadVector());
    }
}
