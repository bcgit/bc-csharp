using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.IO.Compression;

namespace Org.BouncyCastle.Cms
{
    /**
     * containing class for an CMS Compressed Data object
     */
    public class CmsCompressedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly CompressedData m_compressedData;

        public CmsCompressedData(byte[] compressedData)
            : this(CmsUtilities.ReadContentInfo(compressedData))
        {
        }

        public CmsCompressedData(Stream compressedDataStream)
            : this(CmsUtilities.ReadContentInfo(compressedDataStream))
        {
        }

        public CmsCompressedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_compressedData = CmsUtilities.SafeGetContent(contentInfo, CompressedData.GetInstance);
        }

        /**
         * Return the uncompressed content.
         *
         * @return the uncompressed content
         * @throws CmsException if there is an exception uncompressing the data.
         */
        public byte[] GetContent() => Decompress(zIn => CmsUtilities.StreamToByteArray(zIn));

        /**
         * Return the uncompressed content, throwing an exception if the data size
         * is greater than the passed in limit. If the content is exceeded getCause()
         * on the CMSException will contain a StreamOverflowException
         *
         * @param limit maximum number of bytes to read
         * @return the content read
         * @throws CMSException if there is an exception uncompressing the data.
         */
        public byte[] GetContent(int limit) => Decompress(zIn => CmsUtilities.StreamToByteArray(zIn, limit));

        public CompressedData CompressedData => m_compressedData;

        /**
         * return the ContentInfo 
         */
        public ContentInfo ContentInfo => m_contentInfo;

        /**
         * return the ASN.1 encoded representation of this object.
         */
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        private byte[] Decompress(Func<Stream, byte[]> converter)
        {
            ContentInfo encapContentInfo = CompressedData.EncapContentInfo;
            Asn1OctetString encapContent = CmsUtilities.SafeGetContent(encapContentInfo, Asn1OctetString.GetInstance);

            try
            {
                using (Stream zIn = ZLib.DecompressInput(encapContent.GetOctetStream()))
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
    }
}
