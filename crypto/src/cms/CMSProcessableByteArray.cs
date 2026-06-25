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

        public CmsProcessableByteArray(byte[] bytes)
            : this(CmsObjectIdentifiers.Data, bytes)
        {
        }

        public CmsProcessableByteArray(DerObjectIdentifier type, byte[] bytes)
        {
            m_type = type;
            m_bytes = bytes;
        }

        public byte[] GetByteArray() => Arrays.Clone(m_bytes);

        [Obsolete("Use 'ContentType' instead")]
        public DerObjectIdentifier Type => m_type;

        public virtual Stream GetInputStream() => new MemoryStream(m_bytes, writable: false);

        public virtual void Write(Stream zOut) => zOut.Write(m_bytes, 0, m_bytes.Length);

        public DerObjectIdentifier ContentType => m_type;
    }
}
