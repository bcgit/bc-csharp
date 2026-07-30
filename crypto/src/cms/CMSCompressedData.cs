using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.IO.Compression;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Represents a CMS CompressedData message. Parse an encoded message, then decompress via
    /// <see cref="GetContent()"/> or <see cref="GetContentStream()"/>.
    /// </summary>
    public class CmsCompressedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly CompressedData m_compressedData;

        /// <summary>Creates an instance from an encoded CompressedData message.</summary>
        /// <param name="compressedData">The DER-encoded CMS ContentInfo bytes.</param>
        public CmsCompressedData(byte[] compressedData)
            : this(CmsUtilities.ReadContentInfo(compressedData))
        {
        }

        /// <summary>Creates an instance from an encoded CompressedData message.</summary>
        /// <param name="compressedDataStream">A stream containing the DER-encoded CMS ContentInfo.</param>
        public CmsCompressedData(Stream compressedDataStream)
            : this(CmsUtilities.ReadContentInfo(compressedDataStream))
        {
        }

        /// <summary>Creates an instance from a parsed CMS ContentInfo structure.</summary>
        /// <param name="contentInfo">The CMS ContentInfo wrapping a CompressedData object.</param>
        /// <exception cref="ArgumentNullException"><paramref name="contentInfo"/> is null.</exception>
        public CmsCompressedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_compressedData = CmsUtilities.SafeGetContent(contentInfo, CompressedData.GetInstance);
        }

        /// <summary>Gets the outer CMS ContentInfo content type (compressed-data).</summary>
        public DerObjectIdentifier ContentType => m_contentInfo.ContentType;

        /// <summary>Gets the content type of the encapsulated content before compression.</summary>
        public DerObjectIdentifier CompressedContentType => m_compressedData.EncapContentInfo.ContentType;

        /// <summary>Returns a typed stream over the decompressed content.</summary>
        /// <returns>A stream over the uncompressed content.</returns>
        public CmsTypedStream GetContentStream() => new CmsTypedStream(CompressedContentType, Decompress());

        /// <summary>Returns the decompressed content.</summary>
        /// <returns>The uncompressed content octets.</returns>
        /// <exception cref="CmsException">Thrown if the compressed data cannot be read.</exception>
        public byte[] GetContent() => Decompress(zIn => CmsUtilities.StreamToByteArray(zIn));

        /// <summary>
        /// Returns the decompressed content, throwing if the uncompressed size would exceed <paramref name="limit"/>.
        /// </summary>
        /// <param name="limit">The maximum number of decompressed bytes to read.</param>
        /// <returns>The uncompressed content octets.</returns>
        /// <exception cref="CmsException">
        /// Thrown if the compressed data cannot be read. If <paramref name="limit"/> is exceeded, the inner exception
        /// may be a <see cref="StreamOverflowException"/>.
        /// </exception>
        public byte[] GetContent(int limit) => Decompress(zIn => CmsUtilities.StreamToByteArray(zIn, limit));

        /// <summary>Gets the underlying ASN.1 CompressedData structure.</summary>
        public CompressedData CompressedData => m_compressedData;

        /// <summary>Gets the CMS ContentInfo wrapper for this message.</summary>
        public ContentInfo ContentInfo => m_contentInfo;

        /// <summary>Returns the DER encoding of this message.</summary>
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        private byte[] Decompress(Func<Stream, byte[]> converter)
        {
            var zIn = Decompress();

            try
            {
                using (zIn)
                {
                    return converter(zIn);
                }
            }
            catch (CmsException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CmsException("exception reading compressed stream.", e);
            }
        }

        private Stream Decompress()
        {
            ContentInfo encapContentInfo = m_compressedData.EncapContentInfo;
            Asn1OctetString encapContent = CmsUtilities.SafeGetContent(encapContentInfo, Asn1OctetString.GetInstance);
            return ZLib.DecompressInput(encapContent.GetOctetStream());
        }
    }
}
