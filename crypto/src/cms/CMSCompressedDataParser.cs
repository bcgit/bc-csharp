using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.IO.Compression;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Streaming parser for CMS CompressedData messages, the counterpart to <see cref="CmsCompressedData"/>.
    /// </summary>
    /// <remarks>
    /// The constructor reads only the outer CMS ContentInfo header from the supplied stream. Compressed content is
    /// drained lazily via <see cref="GetContent()"/> and reading from the returned <see cref="CmsTypedStream"/>.
    /// <para>The supplied stream is not closed automatically. Dispose this parser to close the underlying stream,
    /// or close it yourself.</para>
    /// <para>This class does not introduce buffering. For large inputs, pass a buffered stream with a suitably
    /// large buffer size.</para>
    /// <para>Example:</para>
    /// <code>
    /// CmsCompressedDataParser cp = new CmsCompressedDataParser(inputStream);
    /// using CmsTypedStream content = cp.GetContent();
    /// Process(content.ContentStream);
    /// </code>
    /// </remarks>
    public class CmsCompressedDataParser
        : CmsContentInfoParser
    {
        /// <summary>Creates a parser from an encoded CompressedData message.</summary>
        /// <param name="compressedData">The DER-encoded CMS ContentInfo bytes.</param>
        public CmsCompressedDataParser(byte[] compressedData)
            : this(new MemoryStream(compressedData, false))
        {
        }

        /// <summary>Creates a parser from an encoded CompressedData message.</summary>
        /// <param name="compressedData">The stream containing the DER-encoded CMS ContentInfo.</param>
        /// <exception cref="System.ArgumentNullException"><paramref name="compressedData"/> is null.</exception>
        /// <exception cref="CmsException">The stream cannot be parsed as CMS ContentInfo.</exception>
        public CmsCompressedDataParser(Stream compressedData)
            : base(compressedData)
        {
        }

        /// <summary>Returns a typed stream over the decompressed content.</summary>
        /// <returns>A stream over the uncompressed content.</returns>
        /// <exception cref="CmsException">Thrown if the compressed content cannot be read.</exception>
        public CmsTypedStream GetContent()
        {
            try
            {
                CompressedDataParser comData = new CompressedDataParser(
                    (Asn1SequenceParser)this.contentInfo.GetContent(Asn1Tags.Sequence));
                ContentInfoParser content = comData.GetEncapContentInfo();

                Asn1OctetStringParser bytes = (Asn1OctetStringParser)content.GetContent(Asn1Tags.OctetString);
                Stream zIn = ZLib.DecompressInput(bytes.GetOctetStream());

                return new CmsTypedStream(content.ContentType, zIn);
            }
            catch (IOException e)
            {
                throw new CmsException("IOException reading compressed content.", e);
            }
        }
    }
}
