using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>General class for generating a compressed CMS message.</summary>
    public class CmsCompressedDataGenerator
    {
        public static readonly string ZLib = CmsObjectIdentifiers.ZlibCompress.Id;

        private static readonly AlgorithmIdentifier ZLibCompressionAlgorithm =
            new AlgorithmIdentifier(CmsObjectIdentifiers.ZlibCompress);

        public CmsCompressedDataGenerator()
        {
        }

        /// <summary>Generate an object that contains an CMS CompressedData.</summary>
        [Obsolete("Use 'Generate(CmsTypedData, string)' instead")]
        public CmsCompressedData Generate(CmsProcessable content, string compressionOid) =>
            Generate(CmsUtilities.GetTypedData(content), compressionOid);

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
