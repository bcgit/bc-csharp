using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

using AlgorithmIdentifier = Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Default signed attributes generator.</summary>
    public class DefaultSignedAttributeTableGenerator
        : CmsAttributeTableGenerator
    {
        private readonly IDictionary<DerObjectIdentifier, object> m_table;

        /// <summary>Initialise to use all defaults.</summary>
        public DefaultSignedAttributeTableGenerator()
        {
            m_table = new Dictionary<DerObjectIdentifier, object>();
        }

        /// <summary>Initialise with some extra attributes or overrides.</summary>
        public DefaultSignedAttributeTableGenerator(AttributeTable attributeTable)
        {
            if (attributeTable != null)
            {
                m_table = attributeTable.ToDictionary();
            }
            else
            {
                m_table = new Dictionary<DerObjectIdentifier, object>();
            }
        }

        /// <summary>Returns a populated <see cref=" AttributeTable"/>.</summary>
        public virtual AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
        {
            var table = CreateStandardAttributeTable(parameters);
            return new AttributeTable(table);
        }

        /// <summary>
        /// Create a standard attribute table from the passed in parameters - this will normally include contentType,
        /// signingTime, and messageDigest.
        /// </summary>
        /// <remarks>
        /// If the constructor using an AttributeTable was used, entries in it for contentType, signingTime, and
        /// messageDigest will override the generated ones.
        /// </remarks>
        /// <returns>A filled-in dictionary of attributes.</returns>
        protected virtual IDictionary<DerObjectIdentifier, object> CreateStandardAttributeTable(
            IDictionary<CmsAttributeTableParameter, object> parameters)
        {
            var std = new Dictionary<DerObjectIdentifier, object>(m_table);
            AddMissingStandardAttributes(parameters, std);
            return std;
        }

        private static void AddMissingStandardAttributes(IDictionary<CmsAttributeTableParameter, object> parameters,
            IDictionary<DerObjectIdentifier, object> std)
        {
            if (!std.ContainsKey(CmsAttributes.ContentType))
            {
                // contentType will be absent if we're trying to generate a counter signature.
                if (parameters.TryGetValue(CmsAttributeTableParameter.ContentType, out var contentType))
                {
                    Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.ContentType,
                        new DerSet((DerObjectIdentifier)contentType));
                    std[attr.AttrType] = attr;
                }
            }

            if (!std.ContainsKey(CmsAttributes.SigningTime))
            {
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.SigningTime,
                    new DerSet(new Time(DateTime.UtcNow)));
                std[attr.AttrType] = attr;
            }

            if (!std.ContainsKey(CmsAttributes.MessageDigest))
            {
                byte[] messageDigest = (byte[])parameters[CmsAttributeTableParameter.Digest];
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.MessageDigest,
                    new DerSet(new DerOctetString(messageDigest)));
                std[attr.AttrType] = attr;
            }

            // TODO[api] After removing legacy CmsSignedGenerator.GetBaseParameters, SignatureAlgorithmIdentifier can be
            // assumed present here
            if (!std.ContainsKey(CmsAttributes.CmsAlgorithmProtect) &&
                parameters.TryGetValue(CmsAttributeTableParameter.SignatureAlgorithmIdentifier, out var valueObject))
            {
                var digestAlgID = (AlgorithmIdentifier)parameters[CmsAttributeTableParameter.DigestAlgorithmIdentifier];
                //var signatureAlgID = (AlgorithmIdentifier)
                //    parameters[CmsAttributeTableParameter.SignatureAlgorithmIdentifier];
                var signatureAlgID = (AlgorithmIdentifier)valueObject;
                var algorithmProtection = new CmsAlgorithmProtection(digestAlgID, CmsAlgorithmProtection.Signature,
                    signatureAlgID);
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.CmsAlgorithmProtect,
                    new DerSet(algorithmProtection));
                std[attr.AttrType] = attr;
            }
        }
    }
}
