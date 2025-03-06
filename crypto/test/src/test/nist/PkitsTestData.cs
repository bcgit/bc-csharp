using System.Collections.Concurrent;

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
    }
}
