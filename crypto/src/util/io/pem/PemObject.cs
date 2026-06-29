using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
    public class PemObject
        : PemObjectGenerator
    {
        private readonly string m_type;
        private readonly IList<PemHeader> m_headers;
        private readonly byte[] m_content;

        public PemObject(string type, byte[] content)
            : this(type, new List<PemHeader>(), content)
        {
        }

        public PemObject(string type, IList<PemHeader> headers, byte[] content)
        {
            m_type = type;
            m_headers = new List<PemHeader>(headers);
            m_content = content;
        }

        public string Type => m_type;

        public IList<PemHeader> Headers => m_headers;

        public byte[] Content => m_content;

        public PemObject Generate() => this;
    }
}
