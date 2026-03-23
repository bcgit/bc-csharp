using System;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Will be removed")]
    public class OidTokenizer
    {
        private readonly string m_oid;
        private int m_index;

        public OidTokenizer(string oid)
        {
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
            m_index = 0;
        }

        public bool HasMoreTokens => m_index != -1;

        public string NextToken()
        {
            if (m_index == -1)
                return null;

            int end = m_oid.IndexOf('.', m_index);
            if (end == -1)
            {
                string lastToken = m_oid.Substring(m_index);
                m_index = -1;
                return lastToken;
            }

            string nextToken = m_oid.Substring(m_index, end - m_index);
            m_index = end + 1;
            return nextToken;
        }
    }
}
