using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Represents a CMS AuthenticatedData (MAC-protected) message. Parse an encoded message, obtain recipients from
    /// <see cref="GetRecipientInfos"/>, match one with <see cref="RecipientID"/>, recover content via
    /// <see cref="RecipientInformation"/>, and verify integrity with <see cref="GetMac"/>.
    /// </summary>
    public class CmsAuthenticatedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly AuthenticatedData m_authenticatedData;
        private readonly OriginatorInformation m_originatorInformation;
        private readonly RecipientInformationStore m_recipientInfoStore;

        // Derived
        private Asn1.Cms.AttributeTable m_authAttributeTable;
        private Asn1.Cms.AttributeTable m_unauthAttributeTable;

        /// <summary>Creates an instance from an encoded AuthenticatedData message.</summary>
        /// <param name="authData">The DER-encoded CMS ContentInfo bytes.</param>
        public CmsAuthenticatedData(byte[] authData)
            : this(CmsUtilities.ReadContentInfo(authData))
        {
        }

        /// <summary>Creates an instance from an encoded AuthenticatedData message.</summary>
        /// <param name="authData">A stream containing the DER-encoded CMS ContentInfo.</param>
        public CmsAuthenticatedData(Stream authData)
            : this(CmsUtilities.ReadContentInfo(authData))
        {
        }

        /// <summary>Creates an instance from a parsed CMS ContentInfo structure.</summary>
        /// <param name="contentInfo">The CMS ContentInfo wrapping an AuthenticatedData object.</param>
        /// <exception cref="ArgumentNullException"><paramref name="contentInfo"/> is null.</exception>
        /// <exception cref="CmsException">Authenticated attributes cannot be validated.</exception>
        /// <exception cref="NotImplementedException">Authenticated attributes are present in the message.</exception>
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

        /// <summary>Gets the underlying ASN.1 AuthenticatedData structure.</summary>
        public AuthenticatedData AuthenticatedData => m_authenticatedData;

        /// <summary>Gets originator certificates and CRLs carried in the message, or null if absent.</summary>
        public OriginatorInformation OriginatorInformation => m_originatorInformation;

        /// <summary>Returns a copy of the message authentication code (MAC) value.</summary>
        public byte[] GetMac() => Arrays.Clone(m_authenticatedData.Mac.GetOctets());

        /// <summary>Gets the MAC algorithm identifier.</summary>
        public AlgorithmIdentifier MacAlgorithmID => m_authenticatedData.MacAlgorithm;

        /// <summary>Return the object identifier for the MAC algorithm.</summary>
        // TODO[api] Return the OID itself
        public string MacAlgOid => MacAlgorithmID.Algorithm.GetID();

        /// <summary>Returns a store of the intended recipients for this message.</summary>
        public RecipientInformationStore GetRecipientInfos() => m_recipientInfoStore;

        /// <summary>Gets the CMS ContentInfo wrapper for this message.</summary>
        public ContentInfo ContentInfo => m_contentInfo;

        /// <summary>Return a table of the authenticated attributes. Use <see cref="AuthAttributes"/> instead.
        /// </summary>
        [Obsolete("Use 'AuthAttributes' property instead")]
        public Asn1.Cms.AttributeTable GetAuthAttrs() => AuthAttributes;

        /// <summary>Gets a table of authenticated attributes indexed by attribute OID.</summary>
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

        /// <summary>Return a table of the unauthenticated attributes. Use <see cref="UnauthAttributes"/> instead.
        /// </summary>
        [Obsolete("Use 'UnauthAttributes' property instead")]
        public Asn1.Cms.AttributeTable GetUnauthAttrs() => UnauthAttributes;

        /// <summary>Gets a table of unauthenticated attributes indexed by attribute OID.</summary>
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

        /// <summary>Returns the DER encoding of this message.</summary>
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        /// <summary>
        /// Returns the message-digest value carried in authenticated attributes, or null if none is present.
        /// </summary>
        /// <returns>A copy of the message-digest octets, or null when the attribute is absent.</returns>
        /// <exception cref="CmsException">Authenticated attributes are present but invalid.</exception>
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
