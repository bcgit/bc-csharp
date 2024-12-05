using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * class for breaking up an X500 Name into it's component tokens, ala
     * java.util.StringTokenizer. We need this class as some of the
     * lightweight Java environment don't support classes like
     * StringTokenizer.
     */
    public class X509NameTokenizer
    {
        private readonly string m_value;
        private readonly char m_separator;

        private int m_index;

        public X509NameTokenizer(string oid)
            : this(oid, ',')
        {
        }

		public X509NameTokenizer(string	oid, char separator)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (separator == '"' || separator == '\\')
                throw new ArgumentException("reserved separator character", nameof(separator));

            m_value = oid;
            m_separator = separator;
            m_index = oid.Length < 1 ? 0 : -1;
        }

        public bool HasMoreTokens() => m_index < m_value.Length;

		public string NextToken()
        {
            if (m_index >= m_value.Length)
                return null;

            bool quoted = false;
            bool escaped = false;

            int beginIndex = m_index + 1;
            while (++m_index < m_value.Length)
            {
                char c = m_value[m_index];

                if (escaped)
                {
                    escaped = false;
                }
                else if (c == '"')
                {
                    quoted = !quoted;
                }
                else if (quoted)
                {
                }
                else if (c == '\\')
                {
                    escaped = true;
                }
                else if (c == m_separator)
                {
                    return m_value.Substring(beginIndex, m_index - beginIndex);
                }
            }

            if (escaped || quoted)
                throw new ArgumentException("badly formatted directory string");

            return m_value.Substring(beginIndex, m_index - beginIndex);
        }
    }
}
