using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Content that has a CMS content type.</summary>
    public interface CmsTypedData
        : CmsProcessable
    {
        /// <summary>Gets the object identifier of the content type.</summary>
        DerObjectIdentifier ContentType { get; }
    }
}
