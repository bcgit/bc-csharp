using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    public interface CmsTypedData
        : CmsProcessable
    {
        DerObjectIdentifier ContentType { get; }
    }
}
