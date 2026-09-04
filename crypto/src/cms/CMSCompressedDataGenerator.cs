using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Generator for CMS CompressedData messages. Compresses content with ZLIB and returns a
    /// <see cref="CmsCompressedData"/> instance (read-side: Batch 15d, #703).
    /// </summary>
    public class CmsCompressedDataGenerator
    {
        /// <summary>The object identifier for ZLIB compression (<c>id-zlibCompress</c>).</summary>
        public static readonly string ZLib = CmsObjectIdentifiers.ZlibCompress.Id;

        private static readonly AlgorithmIdentifier ZLibCompressionAlgorithm =
            new AlgorithmIdentifier(CmsObjectIdentifiers.ZlibCompress);

        /// <summary>Creates a compressed-data generator.</summary>
        public CmsCompressedDataGenerator()
        {
        }

        /// <summary>Generate an object that contains an CMS CompressedData.</summary>
        [Obsolete("Use 'Generate(CmsTypedData, string)' instead")]
        public CmsCompressedData Generate(CmsProcessable content, string compressionOid) =>
            Generate(CmsUtilities.GetTypedData(content), compressionOid);

        /// <summary>Generates a CMS CompressedData message for <paramref name="content"/>.</summary>
        /// <param name="content">The content to compress.</param>
        /// <param name="compressionOid">The compression algorithm OID (currently only <see cref="ZLib"/>).</param>
        /// <returns>A compressed-data structure.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="compressionOid"/> is not supported.
        /// </exception>
        /// <exception cref="CmsException">Thrown if the content cannot be compressed.</exception>
        public CmsCompressedData Generate(CmsTypedData content, string compressionOid)
        {
            if (ZLib != compressionOid)
                throw new ArgumentException("Unsupported compression algorithm: " + compressionOid,
                    nameof(compressionOid));

            Asn1OctetString encapContent;
            try
            {
                MemoryStream bOut = new MemoryStream();
                using (var zOut = Utilities.IO.Compression.ZLib.CompressOutput(bOut, -1))
                {
                    content.Write(zOut);
                }
                encapContent = BerOctetString.WithContents(bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new CmsException("exception encoding data.", e);
            }

            var encapContentInfo = new ContentInfo(content.ContentType, encapContent);

            var compressedData = new CompressedData(ZLibCompressionAlgorithm, encapContentInfo);

            var contentInfo = new ContentInfo(CmsObjectIdentifiers.CompressedData, compressedData);

            return new CmsCompressedData(contentInfo);
        }
    }
}
