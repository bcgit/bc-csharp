using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
	/// <remarks>
	/// The 'Signature' parameter is only available when generating unsigned attributes.
	/// </remarks>
	public enum CmsAttributeTableParameter
	{
		ContentType, Digest, Signature, DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier
    }

	public interface CmsAttributeTableGenerator
	{
		AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters);
	}
}
