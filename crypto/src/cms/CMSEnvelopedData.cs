using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Represents a CMS EnvelopedData message. Parse an encoded message, obtain recipients from
    /// <see cref="GetRecipientInfos"/>, match one with <see cref="RecipientID"/>, then decrypt via
    /// <see cref="RecipientInformation"/>.
    /// </summary>
    public class CmsEnvelopedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly EnvelopedData m_envelopedData;
        private readonly OriginatorInformation m_originatorInformation;
        private readonly RecipientInformationStore m_recipientInfoStore;

        /// <summary>Creates an instance from an encoded EnvelopedData message.</summary>
        /// <param name="envelopedData">The DER-encoded CMS ContentInfo bytes.</param>
        public CmsEnvelopedData(byte[] envelopedData)
            : this(CmsUtilities.ReadContentInfo(envelopedData))
        {
        }

        /// <summary>Creates an instance from an encoded EnvelopedData message.</summary>
        /// <param name="envelopedData">A stream containing the DER-encoded CMS ContentInfo.</param>
        public CmsEnvelopedData(Stream envelopedData)
            : this(CmsUtilities.ReadContentInfo(envelopedData))
        {
        }

        /// <summary>Creates an instance from a parsed CMS ContentInfo structure.</summary>
        /// <param name="contentInfo">The CMS ContentInfo wrapping an EnvelopedData object.</param>
        /// <exception cref="ArgumentNullException"><paramref name="contentInfo"/> is null.</exception>
        public CmsEnvelopedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_envelopedData = CmsUtilities.SafeGetContent(contentInfo, EnvelopedData.GetInstance);

            var originatorInfo = m_envelopedData.OriginatorInfo;
            m_originatorInformation = originatorInfo == null ? null : new OriginatorInformation(originatorInfo);

            //
            // read the recipients
            //
            Asn1Set recipientInfos = m_envelopedData.RecipientInfos;

            //
            // read the encrypted content info
            //
            var encryptedContentInfo = m_envelopedData.EncryptedContentInfo;

            CmsReadable readable = CmsUtilities.ProcessEncryptedContent(encryptedContentInfo);
            CmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsEnvelopedSecureReadable(
                encryptedContentInfo.ContentEncryptionAlgorithm, readable);

            //
            // build the RecipientInformationStore
            //
            m_recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(recipientInfos, secureReadable);
        }

        /// <summary>Gets originator certificates and CRLs carried in the message, or null if absent.</summary>
        public OriginatorInformation OriginatorInformation => m_originatorInformation;

        /// <summary>Gets the content-encryption algorithm identifier.</summary>
        public AlgorithmIdentifier EncryptionAlgorithmID =>
            EnvelopedData.EncryptedContentInfo.ContentEncryptionAlgorithm;

        /// <summary>Return the object identifier for the content-encryption algorithm.</summary>
        // TODO[api] Return the OID itself
        public string EncryptionAlgOid => EncryptionAlgorithmID.Algorithm.GetID();

        /// <summary>Returns a store of the intended recipients for this message.</summary>
        public RecipientInformationStore GetRecipientInfos() => m_recipientInfoStore;

        /// <summary>Gets the CMS ContentInfo wrapper for this message.</summary>
        public ContentInfo ContentInfo => m_contentInfo;

        /// <summary>Gets the underlying ASN.1 EnvelopedData structure.</summary>
        public EnvelopedData EnvelopedData => m_envelopedData;

        /// <summary>Returns a table of unprotected attributes indexed by attribute OID, or null if absent.</summary>
        public Asn1.Cms.AttributeTable GetUnprotectedAttributes() => EnvelopedData.UnprotectedAttrs?.ToAttributeTable();

        /// <summary>Returns the DER encoding of this message.</summary>
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();
    }
}
