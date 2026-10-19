using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    /// <remarks>
    /// The 'Signature' parameter is only available when generating unsigned attributes.
    /// </remarks>
    public enum CmsAttributeTableParameter
    {
        ContentType, Digest, Signature, DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier, MacAlgorithmIdentifier,
    }

    /// <summary>Generator for the signed or unsigned attributes of a CMS signer or authenticated data.</summary>
    public interface CmsAttributeTableGenerator
    {
        /// <summary>Return the attributes to include.</summary>
        /// <param name="parameters">
        /// Values available to the generator, keyed by <see cref="CmsAttributeTableParameter"/>.
        /// </param>
        /// <returns>The attribute table.</returns>
        AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters);
    }
}
