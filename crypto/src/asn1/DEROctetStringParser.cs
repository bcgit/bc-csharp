using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public class DerOctetStringParser
        : Asn1OctetStringParser
    {
        private readonly DefiniteLengthInputStream m_stream;

        internal DerOctetStringParser(DefiniteLengthInputStream stream)
        {
            m_stream = stream;
        }

        public Stream GetOctetStream() => m_stream;

        public Asn1Object ToAsn1Object()
        {
            try
            {
                return DerOctetString.WithContents(m_stream.ToArray());
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("IOException converting stream to byte array: " + e.Message, e);
            }
        }
    }
}
