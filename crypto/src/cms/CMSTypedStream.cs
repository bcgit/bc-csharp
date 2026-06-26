using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    public class CmsTypedStream
        : IDisposable
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly Stream m_contentStream;

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

        public CmsTypedStream(DerObjectIdentifier contentType, Stream contentStream)
            : this(contentType, contentStream, Streams.DefaultBufferSize)
        {
        }

        public CmsTypedStream(DerObjectIdentifier contentType, Stream contentStream, int bufSize)
        {
            m_contentType = contentType;
            m_contentStream = new BufferedFilterStream(contentStream, bufSize);
        }

        [Obsolete("Use 'ContentTypeOid' instead")]
        public string ContentType => m_contentType.GetID();

        public DerObjectIdentifier ContentTypeOid => m_contentType;

        public Stream ContentStream => m_contentStream;

        public void Drain()
        {
            using (m_contentStream)
            {
                Streams.Drain(m_contentStream);
            }
        }

        #region IDisposable

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

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
