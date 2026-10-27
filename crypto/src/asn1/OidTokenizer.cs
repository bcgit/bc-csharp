using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Splits a dotted-decimal object identifier into its components.</summary>
    [Obsolete("Will be removed")]
    public class OidTokenizer
    {
        private readonly string m_oid;
        private int m_index;

        /// <summary>Create a new <see cref="OidTokenizer"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        public OidTokenizer(string oid)
        {
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
            m_index = 0;
        }

        /// <summary>Gets a value indicating whether this has more tokens.</summary>
        public bool HasMoreTokens => m_index != -1;

        /// <summary>Get the next token of the dotted-decimal string.</summary>
        /// <returns>The next token, or null if there are no more.</returns>
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
