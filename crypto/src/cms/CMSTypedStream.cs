using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>A stream of CMS content together with its content type.</summary>
    public class CmsTypedStream
        : IDisposable
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly Stream m_contentStream;

        /// <summary>Create a stream of content of type <c>data</c>.</summary>
        /// <param name="inStream">The stream.</param>
        public CmsTypedStream(Stream inStream)
            : this(PkcsObjectIdentifiers.Data, inStream)
        {
        }

        [Obsolete("Use 'DerObjectIdentifier' variant instead")]
        public CmsTypedStream(string oid, Stream inStream)
            : this(oid, inStream, Streams.DefaultBufferSize)
        {
        }

        [Obsolete("Use 'DerObjectIdentifier' variant instead")]
        public CmsTypedStream(string oid, Stream inStream, int bufSize)
            : this(new DerObjectIdentifier(oid), inStream, bufSize)
        {
        }

        /// <summary>Create a stream of typed content.</summary>
        /// <param name="contentType">The content type.</param>
        /// <param name="contentStream">The stream.</param>
        public CmsTypedStream(DerObjectIdentifier contentType, Stream contentStream)
            : this(contentType, contentStream, Streams.DefaultBufferSize)
        {
        }

        /// <summary>Create a stream of typed content, with the given buffer size.</summary>
        /// <param name="contentType">The content type.</param>
        /// <param name="contentStream">The stream.</param>
        /// <param name="bufSize">The size of the buffer used when reading.</param>
        public CmsTypedStream(DerObjectIdentifier contentType, Stream contentStream, int bufSize)
        {
            m_contentType = contentType;
            m_contentStream = new BufferedFilterStream(contentStream, bufSize);
        }

        [Obsolete("Use 'ContentTypeOid' instead")]
        public string ContentType => m_contentType.GetID();

        /// <summary>Gets the content type.</summary>
        public DerObjectIdentifier ContentTypeOid => m_contentType;

        /// <summary>Gets the (buffered) content stream.</summary>
        public Stream ContentStream => m_contentStream;

        /// <summary>Read the stream to its end, discarding the data, then dispose of it.</summary>
        public void Drain()
        {
            using (m_contentStream)
            {
                Streams.Drain(m_contentStream);
            }
        }

        #region IDisposable

        /// <summary>Dispose of the content stream.</summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Dispose of the content stream.</summary>
        /// <param name="disposing">true when called from <see cref="Dispose()"/>.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_contentStream.Dispose();
            }
        }

        #endregion
    }
}
