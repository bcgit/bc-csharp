using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Containing class for a CMS AuthenticatedData object.</summary>
    public class CmsAuthenticatedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly AuthenticatedData m_authenticatedData;
        private readonly OriginatorInformation m_originatorInformation;
        private readonly RecipientInformationStore m_recipientInfoStore;

        // Derived
        private Asn1.Cms.AttributeTable m_authAttributeTable;
        private Asn1.Cms.AttributeTable m_unauthAttributeTable;

        public CmsAuthenticatedData(byte[] authData)
            : this(CmsUtilities.ReadContentInfo(authData))
        {
        }

        public CmsAuthenticatedData(Stream authData)
            : this(CmsUtilities.ReadContentInfo(authData))
        {
        }

        public CmsAuthenticatedData(ContentInfo contentInfo)
        {
            m_contentInfo = contentInfo ?? throw new ArgumentNullException(nameof(contentInfo));
            m_authenticatedData = CmsUtilities.SafeGetContent(contentInfo, AuthenticatedData.GetInstance);

            var originatorInfo = m_authenticatedData.OriginatorInfo;
            m_originatorInformation = originatorInfo == null ? null : new OriginatorInformation(originatorInfo);

            //
            // read the recipients
            //
            Asn1Set recipientInfos = m_authenticatedData.RecipientInfos;

            //
            // read the authenticated content info
            //
            ContentInfo encapContentInfo = m_authenticatedData.EncapsulatedContentInfo;

            CmsReadable readable = CmsUtilities.ProcessContentOctetString(encapContentInfo);

            // RFC 6211 Validate Algorithm Protection attribute if present
            VerifyAlgorithmProtectionAttribute();

            // TODO Verify other attributes; for message-digest need the calculated content-digest (if any) to compare

            //
            // build the RecipientInformationStore
            //
            var authAttrs = m_authenticatedData.AuthAttrs;
            if (authAttrs == null)
            {
                CmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsAuthenticatedSecureReadable(
                    m_authenticatedData.MacAlgorithm, readable);
                m_recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(recipientInfos, secureReadable);
                return;
            }

            throw new NotImplementedException();

            //try
            //{
            //    CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable(
            //        digestCalculatorProvider.get(authData.getDigestAlgorithm()), encInfo.getContentType(), readable);
            //    secureReadable.setAuthAttrSet(authAttrs);
            //    this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(recipientInfos, this.macAlg, secureReadable);
            //}
            //catch (OperatorCreationException e)
            //{
            //    throw new CMSException("unable to create digest calculator: " + e.getMessage(), e);
            //}
        }

        public AuthenticatedData AuthenticatedData => m_authenticatedData;

        public OriginatorInformation OriginatorInformation => m_originatorInformation;

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

        public ContentInfo ContentInfo => m_contentInfo;

        /// <summary>Return a table of the digested attributes indexed by the OID of the attribute.</summary>
        [Obsolete("Use 'AuthAttributes' property instead")]
        public Asn1.Cms.AttributeTable GetAuthAttrs() => AuthAttributes;

        /// <summary>Return a table of the authenticated attributes - indexed by the OID of the attribute.</summary>
        public Asn1.Cms.AttributeTable AuthAttributes
        {
            get
            {
                if (m_authAttributeTable == null)
                {
                    m_authAttributeTable = m_authenticatedData.AuthAttrs?.ToAttributeTable();
                }
                return m_authAttributeTable;
            }
        }

        /// <summary>Return a table of the undigested attributes indexed by the OID of the attribute.</summary>
        [Obsolete("Use 'AuthAttributes' property instead")]
        public Asn1.Cms.AttributeTable GetUnauthAttrs() => UnauthAttributes;

        /// <summary>Return a table of the unauthenticated attributes - indexed by the OID of the attribute.</summary>
        public Asn1.Cms.AttributeTable UnauthAttributes
        {
            get
            {
                if (m_unauthAttributeTable == null)
                {
                    m_unauthAttributeTable = m_authenticatedData.UnauthAttrs?.ToAttributeTable();
                }
                return m_unauthAttributeTable;
            }
        }

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        public byte[] GetContentDigest()
        {
            // TODO Full validation; this is syntactic validation on access only; the actual digest is not checked 
            Asn1Encodable validMessageDigest = GetSingleValuedAuthAttribute(CmsAttributes.MessageDigest,
                "message-digest");
            if (validMessageDigest == null)
            {
                if (m_authenticatedData.AuthAttrs != null)
                    throw new CmsException("the message-digest authenticated attribute type MUST be present when there are any authenticated attributes present");
            }
            else
            {
                if (!(validMessageDigest is  Asn1OctetString authMessageDigest))
                    throw new CmsException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");

                return Arrays.Clone(authMessageDigest.GetOctets());
            }

            return null;
        }

        private Asn1Encodable GetSingleValuedAuthAttribute(DerObjectIdentifier attrOid, string printableName)
        {
            var unauthAttributes = UnauthAttributes;
            if (unauthAttributes != null && unauthAttributes.HasAny(attrOid))
                throw new CmsException($"The {printableName} attribute MUST NOT be an unauthenticated attribute");

            var authAttributes = AuthAttributes;
            if (authAttributes == null)
                return null;

            Asn1EncodableVector v = authAttributes.GetAll(attrOid);
            switch (v.Count)
            {
            case 0:
                return null;
            case 1:
            {
                Asn1.Cms.Attribute t = (Asn1.Cms.Attribute)v[0];
                Asn1Set attrValues = t.AttrValues;

                if (attrValues.Count != 1)
                    throw new CmsException($"A {printableName} attribute MUST have a single attribute value");

                return attrValues[0];
            }
            default:
                throw new CmsException(
                    $"The AuthAttributes in an AuthenticatedData MUST NOT include multiple instances of the {printableName} attribute");
            }
        }

        /// <summary>RFC 6211 Validate Algorithm Protection attribute if present.</summary>
        private void VerifyAlgorithmProtectionAttribute()
        {
            Asn1Encodable validAlgorithmProtection = GetSingleValuedAuthAttribute(CmsAttributes.CmsAlgorithmProtect,
                "cmsAlgorithmProtect");
            if (validAlgorithmProtection != null)
            {
                var algorithmProtection = CmsAlgorithmProtection.GetInstance(validAlgorithmProtection);

                if (!CmsUtilities.IsEquivalent(algorithmProtection.DigestAlgorithm, m_authenticatedData.DigestAlgorithm))
                    throw new CmsException("CMS Algorithm Protection check failed for digestAlgorithm");

                if (!CmsUtilities.IsEquivalent(algorithmProtection.MacAlgorithm, m_authenticatedData.MacAlgorithm))
                    throw new CmsException("CMS Algorithm Protection check failed for macAlgorithm");
            }
        }
    }
}
