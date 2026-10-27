using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Base class for generators of CMS authenticated data.</summary>
    public class CmsAuthenticatedGenerator
        : CmsEnvelopedGenerator
    {
        internal CmsAttributeTableGenerator m_authGen = null;
        internal CmsAttributeTableGenerator m_unauthGen = null;

        /// <summary>Create a generator using the default source of randomness.</summary>
        public CmsAuthenticatedGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsAuthenticatedGenerator(SecureRandom random)
            : base(random)
        {
        }

        /// <summary>Gets or sets the generator for the authenticated attributes.</summary>
        public CmsAttributeTableGenerator AuthenticatedAttributeGenerator
        {
            get { return m_authGen; }
            set { m_authGen = value; }
        }

        /// <summary>Gets or sets the generator for the unauthenticated attributes.</summary>
        public CmsAttributeTableGenerator UnauthenticatedAttributeGenerator
        {
            get { return m_unauthGen; }
            set { m_unauthGen = value; }
        }

        internal IDictionary<CmsAttributeTableParameter, object> GetBaseParameters(DerObjectIdentifier contentType,
            AlgorithmIdentifier digAlgID, AlgorithmIdentifier macAlgID, byte[] hash)
        {
            var param = new Dictionary<CmsAttributeTableParameter, object>();
            param[CmsAttributeTableParameter.ContentType] = contentType;
            param[CmsAttributeTableParameter.DigestAlgorithmIdentifier] = digAlgID;
            param[CmsAttributeTableParameter.Digest] = hash.Clone();
            param[CmsAttributeTableParameter.MacAlgorithmIdentifier] = macAlgID;
            return param;
        }
    }
}
