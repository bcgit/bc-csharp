using System;

namespace Org.BouncyCastle.Asn1
{
    // TODO[asn1] Replace with BerExternalParser, DLExternalParser (currently functions as DLExternalParser already)
    public class DerExternalParser
        : Asn1Encodable
    {
        private readonly Asn1StreamParser m_parser;

        internal DerExternalParser(Asn1StreamParser parser)
        {
            m_parser = parser;
        }

        public IAsn1Convertible ReadObject() => m_parser.ReadObject();

        public override Asn1Object ToAsn1Object() => Parse(m_parser);

        internal static DLExternal Parse(Asn1StreamParser sp)
        {
            var seq = new DLSequence(sp.ReadVector());

            try
            {
                return DLExternal.FromSequence(seq);
            }
            catch (ArgumentException e)
            {
                throw new Asn1Exception("corrupted stream detected", e);
            }
        }
    }
}
