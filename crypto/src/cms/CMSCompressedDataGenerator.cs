using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /**
     * General class for generating a compressed CMS message.
     * <p>
     * A simple example of usage.</p>
     * <p>
     * <pre>
     *      CMSCompressedDataGenerator fact = new CMSCompressedDataGenerator();
     *      CMSCompressedData data = fact.Generate(content, algorithm);
     * </pre>
     * </p>
     */
    public class CmsCompressedDataGenerator
    {
        public static readonly string ZLib = CmsObjectIdentifiers.ZlibCompress.Id;

        public CmsCompressedDataGenerator()
        {
        }

        /**
        * Generate an object that contains an CMS Compressed Data
        */
        public CmsCompressedData Generate(CmsProcessable content, string compressionOid)
        {
            if (ZLib != compressionOid)
                throw new ArgumentException("Unsupported compression algorithm: " + compressionOid,
                    nameof(compressionOid));

            AlgorithmIdentifier comAlgId;
            Asn1OctetString comOcts;

            try
            {
                MemoryStream bOut = new MemoryStream();

                using (var zOut = Utilities.IO.Compression.ZLib.CompressOutput(bOut, -1))
                {
                    content.Write(zOut);
                }

                comAlgId = new AlgorithmIdentifier(CmsObjectIdentifiers.ZlibCompress);
                comOcts = new BerOctetString(bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new CmsException("exception encoding data.", e);
            }

            ContentInfo comContent = new ContentInfo(CmsObjectIdentifiers.Data, comOcts);
            ContentInfo contentInfo = new ContentInfo(
                CmsObjectIdentifiers.CompressedData,
                new CompressedData(comAlgId, comContent));

            return new CmsCompressedData(contentInfo);
        }
    }
}
