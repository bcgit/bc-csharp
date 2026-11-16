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

        /// <summary>Parse a DigestedData message from its encoding.</summary>
        /// <param name="digestedData">The encoded ContentInfo.</param>
        /// <exception cref="CmsException">The data cannot be parsed.</exception>
        public CmsDigestedData(byte[] digestedData)
            : this(CmsUtilities.ReadContentInfo(digestedData))
        {
        }

        /// <summary>Parse a DigestedData message from a stream.</summary>
        /// <param name="digestedData">A stream containing the encoded ContentInfo.</param>
        /// <exception cref="CmsException">The data cannot be parsed.</exception>
        public CmsDigestedData(Stream digestedData)
            : this(CmsUtilities.ReadContentInfo(digestedData))
        {
        }

        /// <summary>Create from a ContentInfo structure.</summary>
        /// <param name="contentInfo">The ContentInfo wrapping a DigestedData.</param>
        /// <exception cref="ArgumentNullException"><paramref name="contentInfo"/> is null.</exception>
        /// <exception cref="CmsException">The content is not a DigestedData structure.</exception>
        public CmsDigestedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_digestedData = CmsUtilities.SafeGetContent(contentInfo, DigestedData.GetInstance);
        }

        /// <summary>Gets the underlying ContentInfo.</summary>
        public ContentInfo ContentInfo => m_contentInfo;

        /// <summary>Gets the underlying DigestedData structure.</summary>
        public DigestedData DigestedData => m_digestedData;

        /// <summary>Gets the content type of the outer ContentInfo.</summary>
        public DerObjectIdentifier ContentType => m_contentInfo.ContentType;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestedData.DigestAlgorithm;

        /// <summary>Return the digested content.</summary>
        /// <exception cref="CmsException">The content cannot be read.</exception>
        public CmsTypedData GetDigestedContent() => CmsUtilities.ProcessContentOctetString(m_digestedData.EncapContentInfo);

        /// <summary>Return the encoded ContentInfo.</summary>
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        /// <summary>Check that the digest in the message matches the content.</summary>
        /// <returns>true if the digest matches.</returns>
        /// <exception cref="CmsException">The digest cannot be calculated.</exception>
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
