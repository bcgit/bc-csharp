using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Ocsp
{
    public static class OcspUtilities
    {
        public static Asn1OctetString GetNonce(IX509Extension extension) =>
            extension.GetExtension(OcspObjectIdentifiers.PkixOcspNonce, Asn1OctetString.GetInstance);
    }
}
