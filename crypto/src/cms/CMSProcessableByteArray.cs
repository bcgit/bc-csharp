using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>A holding class for a byte array of data to be processed.</summary>
    public class CmsProcessableByteArray
        : CmsTypedData, CmsReadable
    {
        private readonly DerObjectIdentifier m_type;
        private readonly byte[] m_bytes;

        /// <summary>Create content of type <c>data</c> from a byte array.</summary>
        /// <param name="bytes">The content.</param>
        public CmsProcessableByteArray(byte[] bytes)
            : this(CmsObjectIdentifiers.Data, bytes)
        {
        }

        /// <summary>Create typed content from a byte array.</summary>
        /// <param name="type">The content type.</param>
        /// <param name="bytes">The content.</param>
        public CmsProcessableByteArray(DerObjectIdentifier type, byte[] bytes)
        {
            m_type = type;
            m_bytes = bytes;
        }

        /// <summary>Return a copy of the content.</summary>
        public byte[] GetByteArray() => Arrays.Clone(m_bytes);

        [Obsolete("Use 'ContentType' instead")]
        public DerObjectIdentifier Type => m_type;

        /// <summary>Return a read-only stream over the content.</summary>
        public virtual Stream GetInputStream() => new MemoryStream(m_bytes, writable: false);

        /// <summary>Write the content to the stream.</summary>
        /// <param name="zOut">The stream to write to.</param>
        public virtual void Write(Stream zOut) => zOut.Write(m_bytes, 0, m_bytes.Length);

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_type;
    }
}
