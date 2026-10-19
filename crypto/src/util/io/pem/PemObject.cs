using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
    /// <summary>A PEM object: a type, optional headers and binary content.</summary>
    public class PemObject
        : PemObjectGenerator
    {
        private readonly string m_type;
        private readonly IList<PemHeader> m_headers;
        private readonly byte[] m_content;

        /// <summary>Create a new <see cref="PemObject"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="content">The content.</param>
        public PemObject(string type, byte[] content)
            : this(type, new List<PemHeader>(), content)
        {
        }

        /// <summary>Create a new <see cref="PemObject"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="headers">The headers.</param>
        /// <param name="content">The content.</param>
        public PemObject(string type, IList<PemHeader> headers, byte[] content)
        {
            m_type = type;
            m_headers = new List<PemHeader>(headers);
            m_content = content;
        }

        /// <summary>Gets the type.</summary>
        public string Type => m_type;

        /// <summary>Gets the headers.</summary>
        public IList<PemHeader> Headers => m_headers;

        /// <summary>Gets the content.</summary>
        public byte[] Content => m_content;

        /// <inheritdoc/>
        public PemObject Generate() => this;
    }
}
