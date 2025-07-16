using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /**
     * containing class for an CMS Enveloped Data object
     */
    public class CmsEnvelopedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly EnvelopedData m_envelopedData;
        private readonly RecipientInformationStore m_recipientInfoStore;

        // TODO[api] Rename parameter to contentInfo?
        public CmsEnvelopedData(byte[] envelopedData)
            : this(CmsUtilities.ReadContentInfo(envelopedData))
        {
        }

        // TODO[api] Rename parameter to contentInfo?
        public CmsEnvelopedData(Stream envelopedData)
            : this(CmsUtilities.ReadContentInfo(envelopedData))
        {
        }

        public CmsEnvelopedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_envelopedData = EnvelopedData.GetInstance(contentInfo.Content);

            //
            // read the recipients
            //
            Asn1Set recipientInfos = m_envelopedData.RecipientInfos;

            //
            // read the encrypted content info
            //
            var encryptedContentInfo = m_envelopedData.EncryptedContentInfo;

            CmsReadable readable = new CmsProcessableByteArray(encryptedContentInfo.EncryptedContent.GetOctets());
            CmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsEnvelopedSecureReadable(
                encryptedContentInfo.ContentEncryptionAlgorithm, readable);

            //
            // build the RecipientInformationStore
            //
            m_recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(recipientInfos, secureReadable);
        }

        public AlgorithmIdentifier EncryptionAlgorithmID =>
            EnvelopedData.EncryptedContentInfo.ContentEncryptionAlgorithm;

        /**
         * return the object identifier for the content encryption algorithm.
         */
        // TODO[api] Return the OID itself
        public string EncryptionAlgOid => EncryptionAlgorithmID.Algorithm.GetID();

        /**
         * return a store of the intended recipients for this message
         */
        public RecipientInformationStore GetRecipientInfos() => m_recipientInfoStore;

        public ContentInfo ContentInfo => m_contentInfo;

        public EnvelopedData EnvelopedData => m_envelopedData;

        /**
         * return a table of the unprotected attributes indexed by
         * the OID of the attribute.
         */
        public Asn1.Cms.AttributeTable GetUnprotectedAttributes() => EnvelopedData.UnprotectedAttrs?.ToAttributeTable();

        /**
         * return the ASN.1 encoded representation of this object.
         */
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();
    }
}
