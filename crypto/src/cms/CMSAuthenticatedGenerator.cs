using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    public class CmsAuthenticatedGenerator
        : CmsEnvelopedGenerator
    {
        internal CmsAttributeTableGenerator m_authGen = null;
        internal CmsAttributeTableGenerator m_unauthGen = null;

        public CmsAuthenticatedGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsAuthenticatedGenerator(SecureRandom random)
            : base(random)
        {
        }

        public CmsAttributeTableGenerator AuthenticatedAttributeGenerator
        {
            get { return m_authGen; }
            set { m_authGen = value; }
        }

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
