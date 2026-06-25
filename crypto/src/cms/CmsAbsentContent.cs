using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    /// <summary>A class representing null or absent content.</summary>
    public sealed class CmsAbsentContent
        : CmsTypedData, CmsReadable
    {
        private readonly DerObjectIdentifier m_contentType;

        public CmsAbsentContent()
            : this(CmsObjectIdentifiers.Data)
        {
        }

        public CmsAbsentContent(DerObjectIdentifier contentType)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        }

        public Stream GetInputStream() => null;

        public void Write(Stream outStream)
        {
            // do nothing
        }

        public DerObjectIdentifier ContentType => m_contentType;
    }
}
