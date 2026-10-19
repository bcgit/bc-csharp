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

        /// <summary>Create absent content of type <c>data</c>.</summary>
        public CmsAbsentContent()
            : this(CmsObjectIdentifiers.Data)
        {
        }

        /// <summary>Create absent content of the given type.</summary>
        /// <param name="contentType">The content type.</param>
        /// <exception cref="ArgumentNullException"><paramref name="contentType"/> is null.</exception>
        public CmsAbsentContent(DerObjectIdentifier contentType)
        {
            m_contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        }

        /// <summary>Return null, as there is no content.</summary>
        public Stream GetInputStream() => null;

        /// <summary>Do nothing, as there is no content.</summary>
        /// <param name="outStream">The stream, which is not written to.</param>
        public void Write(Stream outStream)
        {
            // do nothing
        }

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentType => m_contentType;
    }
}
