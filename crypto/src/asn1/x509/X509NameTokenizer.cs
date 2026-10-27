using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>
    /// Class for breaking up an X500 Name into it's component tokens.
    /// </summary>
    public class X509NameTokenizer
    {
        private readonly string m_value;
        private readonly char m_separator;

        private int m_index;

        /// <summary>Create a new <see cref="X509NameTokenizer"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        public X509NameTokenizer(string oid)
            : this(oid, ',')
        {
        }

        /// <summary>Create a new <see cref="X509NameTokenizer"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="separator">The separator.</param>
        public X509NameTokenizer(string oid, char separator)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (separator == '"' || separator == '\\')
                throw new ArgumentException("reserved separator character", nameof(separator));

            m_value = oid;
            m_separator = separator;
            m_index = oid.Length < 1 ? 0 : -1;
        }

        /// <summary>Determine whether there are more tokens.</summary>
        /// <returns>true if there are more tokens, false otherwise.</returns>
        public bool HasMoreTokens() => m_index < m_value.Length;

        /// <summary>Get the next token.</summary>
        /// <returns>The next token, or null if there are no more.</returns>
        public string NextToken()
        {
            int length = m_value.Length;
            if (m_index >= length)
                return null;

            bool quoted = false;
            bool escaped = false;

            int beginIndex = m_index + 1;
            while (++m_index < length)
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

        /// <summary>Get the remaining unparsed text.</summary>
        /// <returns>The remaining text.</returns>
        public string Remaining()
        {
            int length = m_value.Length;
            if (m_index >= length)
                return null;

            int beginIndex = m_index + 1;
            m_index = length;
            return m_value.Substring(beginIndex, length - beginIndex);
        }
    }
}
