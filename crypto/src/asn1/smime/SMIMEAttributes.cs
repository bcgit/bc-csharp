using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Smime
{
    /// <summary>The object identifiers of the S/MIME attributes.</summary>
    public abstract class SmimeAttributes
    {
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15</c>.</summary>
        public static readonly DerObjectIdentifier SmimeCapabilities = PkcsObjectIdentifiers.Pkcs9AtSmimeCapabilities;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.2.11</c>.</summary>
        public static readonly DerObjectIdentifier EncrypKeyPref = PkcsObjectIdentifiers.IdAAEncrypKeyPref;
    }
}
