using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Containing class for a CMS DigestedData object.</summary>
    public sealed class CmsDigestedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly DigestedData m_digestedData;

        public CmsDigestedData(byte[] digestedData)
            : this(CmsUtilities.ReadContentInfo(digestedData))
        {
        }

        public CmsDigestedData(Stream digestedData)
            : this(CmsUtilities.ReadContentInfo(digestedData))
        {
        }

        public CmsDigestedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_digestedData = CmsUtilities.SafeGetContent(contentInfo, DigestedData.GetInstance);
        }

        public ContentInfo ContentInfo => m_contentInfo;

        public DigestedData DigestedData => m_digestedData;

        public DerObjectIdentifier ContentType => m_contentInfo.ContentType;

        public AlgorithmIdentifier DigestAlgorithm => m_digestedData.DigestAlgorithm;

        /// <exception cref="CmsException"/>
        public CmsTypedData GetDigestedContent() => CmsUtilities.ProcessContentOctetString(m_digestedData.EncapContentInfo);

        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        /// <exception cref="CmsException"/>
        public bool Verify()
        {
            ContentInfo encapContentInfo = m_digestedData.EncapContentInfo;
            Asn1OctetString encapContent = CmsUtilities.SafeGetContent(encapContentInfo, Asn1OctetString.GetInstance);

            try
            {
                var calculated = DigestUtilities.CalculateDigest(m_digestedData.DigestAlgorithm.Algorithm,
                    encapContent.GetOctets());

                return Arrays.AreEqual(m_digestedData.Digest.GetOctets(), calculated);
            }
            catch (CmsException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CmsException("Unable to process content.", e);
            }
        }
    }
}
