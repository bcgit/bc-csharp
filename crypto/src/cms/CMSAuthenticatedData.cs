using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /**
     * containing class for an CMS Authenticated Data object
     */
    public class CmsAuthenticatedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly AuthenticatedData m_authenticatedData;
        private readonly RecipientInformationStore m_recipientInfoStore;

        // TODO[api] Rename parameter to contentInfo?
        public CmsAuthenticatedData(byte[] authData)
            : this(CmsUtilities.ReadContentInfo(authData))
        {
        }

        // TODO[api] Rename parameter to contentInfo?
        public CmsAuthenticatedData(Stream authData)
            : this(CmsUtilities.ReadContentInfo(authData))
        {
        }

        public CmsAuthenticatedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_authenticatedData = AuthenticatedData.GetInstance(contentInfo.Content);

            //
            // read the recipients
            //
            Asn1Set recipientInfos = m_authenticatedData.RecipientInfos;

            //
            // read the authenticated content info
            //
            ContentInfo encapContentInfo = m_authenticatedData.EncapsulatedContentInfo;
            Asn1OctetString encapContent = Asn1OctetString.GetInstance(encapContentInfo.Content);

            CmsReadable readable = new CmsProcessableByteArray(encapContent.GetOctets());
            CmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsAuthenticatedSecureReadable(
                m_authenticatedData.MacAlgorithm, readable);

            //
            // build the RecipientInformationStore
            //
            m_recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(recipientInfos, secureReadable);
        }

        public AuthenticatedData AuthenticatedData => m_authenticatedData;

        public byte[] GetMac() => Arrays.Clone(m_authenticatedData.Mac.GetOctets());

        public AlgorithmIdentifier MacAlgorithmID => m_authenticatedData.MacAlgorithm;

        /**
         * return the object identifier for the content MAC algorithm.
         */
        // TODO[api] Return the OID itself
        public string MacAlgOid => MacAlgorithmID.Algorithm.GetID();

        /**
         * return a store of the intended recipients for this message
         */
        public RecipientInformationStore GetRecipientInfos() => m_recipientInfoStore;

        /**
         * return the ContentInfo 
         */
        public ContentInfo ContentInfo => m_contentInfo;

        /**
         * return a table of the digested attributes indexed by
         * the OID of the attribute.
         */
        public Asn1.Cms.AttributeTable GetAuthAttrs() => m_authenticatedData.AuthAttrs?.ToAttributeTable();

        /**
         * return a table of the undigested attributes indexed by
         * the OID of the attribute.
         */
        public Asn1.Cms.AttributeTable GetUnauthAttrs() => m_authenticatedData.UnauthAttrs?.ToAttributeTable();

        /**
         * return the ASN.1 encoded representation of this object.
         */
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();
    }
}
