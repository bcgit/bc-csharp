using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Cms
{
    /**
     * containing class for an CMS AuthEnveloped Data object
     */
    internal class CmsAuthEnvelopedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly AuthEnvelopedData m_authEnvelopedData;
        private readonly RecipientInformationStore m_recipientInfoStore;

        // TODO[api] Rename parameter to contentInfo?
        public CmsAuthEnvelopedData(byte[] authEnvData)
            : this(CmsUtilities.ReadContentInfo(authEnvData))
        {
        }

        // TODO[api] Rename parameter to contentInfo?
        public CmsAuthEnvelopedData(Stream authEnvData)
            : this(CmsUtilities.ReadContentInfo(authEnvData))
        {
        }

        public CmsAuthEnvelopedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo;
            m_authEnvelopedData = AuthEnvelopedData.GetInstance(contentInfo.Content);

            //this.originator = m_authEnvelopedData.OriginatorInfo;

            //
            // read the recipients
            //
            Asn1Set recipientInfos = m_authEnvelopedData.RecipientInfos;

            //
            // read the auth-encrypted content info
            //
            //EncryptedContentInfo authEncInfo = m_authEnvelopedData.AuthEncryptedContentInfo;
            //this.authEncAlg = authEncInfo.ContentEncryptionAlgorithm;
            CmsSecureReadable secureReadable = new AuthEnvelopedSecureReadable(this);

            //
            // build the RecipientInformationStore
            //
            m_recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(
                recipientInfos, secureReadable);

            // FIXME These need to be passed to the AEAD cipher as AAD (Additional Authenticated Data)
            //authAttrs = authEnvData.AuthAttrs;
            //mac = authEnvData.Mac.GetOctets();
            //unauthAttrs = authEnvData.UnauthAttrs;
        }

        public AuthEnvelopedData AuthEnvelopedData => m_authEnvelopedData;

        public AlgorithmIdentifier ContentEncryptionAlgorithm =>
            AuthEnvelopedData.AuthEncryptedContentInfo.ContentEncryptionAlgorithm;

        public Asn1.Cms.AttributeTable GetAuthAttrs() => AuthEnvelopedData.AuthAttrs?.ToAttributeTable();

        public Asn1.Cms.AttributeTable GetUnauthAttrs() => AuthEnvelopedData.UnauthAttrs?.ToAttributeTable();

        private class AuthEnvelopedSecureReadable
            : CmsSecureReadable
        {
            private readonly CmsAuthEnvelopedData m_parent;

            internal AuthEnvelopedSecureReadable(CmsAuthEnvelopedData parent)
            {
                m_parent = parent;
            }

            public AlgorithmIdentifier Algorithm => m_parent.ContentEncryptionAlgorithm;

            public object CryptoObject => null;

            public CmsReadable GetReadable(KeyParameter key)
            {
                // TODO Create AEAD cipher instance to decrypt and calculate tag ( MAC)
                throw new CmsException("AuthEnveloped data decryption not yet implemented");

                // RFC 5084 ASN.1 Module
                // -- Parameters for AlgorithmIdentifier
                // 
                // CCMParameters ::= SEQUENCE {
                //   aes-nonce         OCTET STRING (SIZE(7..13)),
                //   aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }
                // 
                // AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
                // 
                // GCMParameters ::= SEQUENCE {
                //   aes-nonce        OCTET STRING, -- recommended size is 12 octets
                //   aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
                // 
                // AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
            }
        }
    }
}
