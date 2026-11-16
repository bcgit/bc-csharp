using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The object identifiers of the CMS attributes.</summary>
    // TODO[api] Make static
    public abstract class CmsAttributes
    {
        /// <summary>The object identifier <c>1.2.840.113549.1.9.3</c>.</summary>
        public static readonly DerObjectIdentifier ContentType = PkcsObjectIdentifiers.Pkcs9AtContentType;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.4</c>.</summary>
        public static readonly DerObjectIdentifier MessageDigest = PkcsObjectIdentifiers.Pkcs9AtMessageDigest;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.5</c>.</summary>
        public static readonly DerObjectIdentifier SigningTime = PkcsObjectIdentifiers.Pkcs9AtSigningTime;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.6</c>.</summary>
        public static readonly DerObjectIdentifier CounterSignature = PkcsObjectIdentifiers.Pkcs9AtCounterSignature;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.4</c>.</summary>
        public static readonly DerObjectIdentifier ContentHint = PkcsObjectIdentifiers.IdAAContentHint;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.52</c>.</summary>
        public static readonly DerObjectIdentifier CmsAlgorithmProtect = PkcsObjectIdentifiers.id_aa_cmsAlgorithmProtect;
    }
}
