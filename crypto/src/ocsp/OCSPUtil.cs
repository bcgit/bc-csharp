using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Utility methods for working with OCSP extensions.</summary>
    public static class OcspUtilities
    {
        /// <summary>Extract the nonce from an object carrying extensions, such as a request or response.</summary>
        /// <param name="extension">The extensions source.</param>
        /// <returns>The nonce value, or null if no nonce extension is present.</returns>
        public static Asn1OctetString GetNonce(IX509Extension extension) =>
            extension.GetExtension(OcspObjectIdentifiers.PkixOcspNonce, Asn1OctetString.GetInstance);
    }
}
