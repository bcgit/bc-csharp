using System.Collections.Concurrent;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests.Nist
{
    internal static class PkitsTestData
    {
        private static readonly ConcurrentDictionary<string, X509Certificate> CertificateCache =
            new ConcurrentDictionary<string, X509Certificate>();
        private static readonly ConcurrentDictionary<string, X509Crl> CrlCache =
            new ConcurrentDictionary<string, X509Crl>();

        internal static X509Certificate GetCertificate(string certificateName)
        {
            return CertificateCache.GetOrAdd(certificateName, key =>
            {
                using (var s = SimpleTest.FindTestResource("PKITS", "certs", $"{key}.crt"))
                {
                    return new X509CertificateParser().ReadCertificate(s);
                }
            });
        }

        internal static X509Crl GetCrl(string crlName)
        {
            return CrlCache.GetOrAdd(crlName, key =>
            {
                using (var s = SimpleTest.FindTestResource("PKITS", "crls", $"{key}.crl"))
                {
                    return new X509CrlParser().ReadCrl(s);
                }
            });
        }

        internal static TrustAnchor GetTrustAnchor(string trustAnchorName)
        {
            X509Certificate cert = GetCertificate(trustAnchorName);
            Asn1OctetString extensionValue = cert.GetExtensionValue(X509Extensions.NameConstraints);

            byte[] nameConstraints = null;
            if (extensionValue != null)
            {
                nameConstraints = NameConstraints.GetInstance(extensionValue.GetOctets()).GetEncoded(Asn1Encodable.Der);
            }

            return new TrustAnchor(cert, nameConstraints);
        }
    }
}
