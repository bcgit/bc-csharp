using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

using AlgorithmIdentifier = Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Default authenticated attributes generator.</summary>
    public class DefaultAuthenticatedAttributeTableGenerator
        : CmsAttributeTableGenerator
    {
        private readonly IDictionary<DerObjectIdentifier, object> m_table;

        /// <summary>Initialise to use all defaults.</summary>
        public DefaultAuthenticatedAttributeTableGenerator()
        {
            m_table = new Dictionary<DerObjectIdentifier, object>();
        }

        /// <summary>Initialise with some extra attributes or overrides.</summary>
        public DefaultAuthenticatedAttributeTableGenerator(AttributeTable attributeTable)
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

        /// <summary>Returns a populated <see cref="AttributeTable"/>.</summary>
        public virtual AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
        {
            var table = CreateStandardAttributeTable(parameters);
            return new AttributeTable(table);
        }

        /// <summary>
        /// Create a standard attribute table from the passed in parameters - this will normally include contentType and
        /// messageDigest.
        /// </summary>
        /// <remarks>
        /// If the constructor using an AttributeTable was used, entries in it for contentType and messageDigest will
        /// override the generated ones.
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
                DerObjectIdentifier contentType = (DerObjectIdentifier)
                    parameters[CmsAttributeTableParameter.ContentType];
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.ContentType,
                    new DerSet(contentType));
                std[attr.AttrType] = attr;
            }

            if (!std.ContainsKey(CmsAttributes.MessageDigest))
            {
                byte[] messageDigest = (byte[])parameters[CmsAttributeTableParameter.Digest];
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.MessageDigest,
                    new DerSet(new DerOctetString(messageDigest)));
                std[attr.AttrType] = attr;
            }

            if (!std.ContainsKey(CmsAttributes.CmsAlgorithmProtect))
            {
                var digestAlgID = (AlgorithmIdentifier)parameters[CmsAttributeTableParameter.DigestAlgorithmIdentifier];
                var macAlgID = (AlgorithmIdentifier)parameters[CmsAttributeTableParameter.MacAlgorithmIdentifier];
                var algorithmProtection = new CmsAlgorithmProtection(digestAlgID, CmsAlgorithmProtection.Mac, macAlgID);
                Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.CmsAlgorithmProtect,
                    new DerSet(algorithmProtection));
                std[attr.AttrType] = attr;
            }
        }
    }
}
