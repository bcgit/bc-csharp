using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
    public class CertPathTest
    {
        internal static readonly byte[] rootCertBin = Base64.Decode(
            "MIIBqzCCARQCAQEwDQYJKoZIhvcNAQEFBQAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMRLUjhPe4YUdLo6EcjKcWUOG7CydFTH53Pr1lWjOkbmszYDpkhCTT9LOsI+disk18nkBxSl8DAHTqV+VxtuTPt64iyi10YxyDeep+DwZG/f8cVQv97U3hA9cLurZ2CofkMLGr6JpSGCMZ9FcstcTdHB4lbErIJ54YqfF4pNOs4/AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAgyrTEFY7ALpeY59jL6xFOLpuPqoBOWrUWv6O+zy5BCU0qiX71r3BpigtxRj+DYcfLIM9FNERDoHu3TthD3nwYWUBtFX8N0QUJIdJabxqAMhLjSC744koiFpCYse5Ye3ZvEdFwDzgAQsJTp5eFGgTZPkPzcdhkFJ2p9+OWs+cb24=");
        internal static readonly byte[] interCertBin = Base64.Decode(
            "MIICSzCCAbSgAwIBAgIBATANBgkqhkiG9w0BAQUFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTA4MDkwNDA0NDUwOFoXDTA4MDkxMTA0NDUwOFowKDEmMCQGA1UEAxMdVGVzdCBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAISS9OOZ2wxzdWny9aVvk4Joq+dwSJ+oqvHUxX3PflZyuiLiCBUOUE4q59dGKdtNX5fIfwyK3cpV0e73Y/0fwfM3m9rOWFrCKOhfeswNTes0w/2PqPVVDDsF/nj7NApuqXwioeQlgTL251RDF4sVoxXqAU7lRkcqwZt3mwqS4KTJAgMBAAGjgY4wgYswRgYDVR0jBD8wPYAUhv8BOT27EB9JaCccJD4YASPP5XWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWCAQEwHQYDVR0OBBYEFL/IwAGOkHzaQyPZegy79CwM5oTFMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAE4TRgUz4sUvZyVdZxqV+XyNRnqXAeLOOqFGYv2D96tQrS+zjd0elVlT6lFrtchZdOmmX7R6/H/tjMWMcTBICZyRYrvK8cCAmDOI+EIdq5p6lj2Oq6Pbw/wruojAqNrpaR6IkwNpWtdOSSupv4IJL+YU9q2YFTh4R1j3tOkPoFGr");
        internal static readonly byte[] finalCertBin = Base64.Decode(
            "MIICRjCCAa+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB8xHTAbBgNVBAMTFFRlc3QgRW5kIENlcnRpZmljYXRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChpUeo0tPYywWKiLlbWKNJBcCpSaLSlaZ+4+yer1AxI5yJIVHP6SAlBghlbD5Qne5ImnN/15cz1xwYAiul6vGKJkVPlFEe2Mr+g/J/WJPQQPsjbZ1G+vxbAwXEDA4KaQrnpjRZFq+CdKHwOjuPLYS/MYQNgdIvDVEQcTbPQ8GaiQIDAQABo4GIMIGFMEYGA1UdIwQ/MD2AFL/IwAGOkHzaQyPZegy79CwM5oTFoSKkIDAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlggEBMB0GA1UdDgQWBBSVkw+VpqBf3zsLc/9GdkK9TzHPwDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQUFAAOBgQBLv/0bVDjzTs/y1vN3FUiZNknEbzupIZduTuXJjqv/vBX+LDPjUfu/+iOCXOSKoRn6nlOWhwB1z6taG2usQkFG8InMkRcPREi2uVgFdhJ/1C3dAWhsdlubjdL926bftXvxnx/koDzyrePW5U96RlOQM2qLvbaky2Giz6hrc3Wl+w==");
        internal static readonly byte[] rootCrlBin = Base64.Decode(
            "MIIBYjCBzAIBATANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlFw0wODA5MDQwNDQ1MDhaFw0wODA5MDQwNzMxNDhaMCIwIAIBAhcNMDgwOTA0MDQ0NTA4WjAMMAoGA1UdFQQDCgEJoFYwVDBGBgNVHSMEPzA9gBSG/wE5PbsQH0loJxwkPhgBI8/ldaEipCAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZYIBATAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOBgQCAbaFCo0BNG4AktVf6jjBLeawP1u0ELYkOCEGvYZE0mBpQ+OvFg7subZ6r3lRIj030nUli28sPFtu5ZQMBNcpE4nS1ziF44RfT3Lp5UgHx9x17Krz781iEyV+7zU8YxYMY9wULD+DCuK294kGKIssVNbmTYXZatBNoXQN5CLIocA==");
        internal static readonly byte[] interCrlBin = Base64.Decode(
            "MIIBbDCB1gIBATANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZRcNMDgwOTA0MDQ0NTA4WhcNMDgwOTA0MDczMTQ4WjAiMCACAQIXDTA4MDkwNDA0NDUwOFowDDAKBgNVHRUEAwoBCaBWMFQwRgYDVR0jBD8wPYAUv8jAAY6QfNpDI9l6DLv0LAzmhMWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWCAQEwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADgYEAEVCr5TKs5yguGgLH+dBzmSPoeSIWJFLsgWwJEit/iUDJH3dgYmaczOcGxIDtbYYHLWIHM+P2YRyQz3MEkCXEgm/cx4y7leAmux5l+xQWgmxFPz+197vaphPeCZo+B7V1CWtm518gcq4mrs9ovfgNqgyFj7KGjcBpWdJE32KMt50=");

        /// <summary>CertPath with a circular reference.</summary>
        internal static readonly byte[] certA = Base64.Decode(
            "MIIC6jCCAlOgAwIBAgIBBTANBgkqhkiG9w0BAQUFADCBjTEPMA0GA1UEAxMGSW50" +
            "ZXIzMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX" +
            "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq" +
            "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ2NTda" +
            "Fw0xNzAzMzAwODQ0MDBaMIGlMScwJQYDVQQDHh4AQQByAG0AaQBuACAASADkAGIA" +
            "ZQByAGwAaQBuAGcxCzAJBgNVBAYTAkNIMQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNV" +
            "BAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNwaGVyZSBBRzEQMA4GA1UECxMHVGVzdGlu" +
            "ZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5AcHJpdmFzcGhlcmUuY29tMIGfMA0GCSqG" +
            "SIb3DQEBAQUAA4GNADCBiQKBgQCfHfyVs5dbxG35H/Thd29qR4NZU88taCu/OWA1" +
            "GdACI02lXWYpmLWiDgnU0ULP+GG8OnVp1IES9fz2zcrXKQ19xZzsen/To3h5sNte" +
            "cJpS00XMM24q/jDwy5NvkBP9YIfFKQ1E/0hFHXcqwlw+b/y/v6YGsZCU2h6QDzc4" +
            "5m0+BwIDAQABo0AwPjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAeBglg" +
            "hkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBBQUAA4GBAJEu" +
            "KiSfIwsY7SfobMLrv2v/BtLhGLi4RnmjiwzBhuv5rn4rRfBpq1ppmqQMJ2pmA67v" +
            "UWCY+mNwuyjHyivpCCyJGsZ9d5H09g2vqxzkDBMz7X9VNMZYFH8j/R3/Cfvqks31" +
            "z0OFslJkeKLa1I0P/dfVHsRKNkLRT3Ws5LKksErQ");

        internal static readonly byte[] certB = Base64.Decode(
            "MIICtTCCAh6gAwIBAgIBBDANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50" +
            "ZXIyMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX" +
            "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq" +
            "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ2Mzha" +
            "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjMxCzAJBgNVBAYTAkNI" +
            "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw" +
            "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A" +
            "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxCXIB" +
            "QRnmVvl2h7Q+0SsRxDLnyM1dJG9jMa+UCCmHy0k/ZHs5VirSbjEJSjkQ9BGeh9SC" +
            "7JwbMpXO7UE+gcVc2RnWUY+MA+fWIeTV4KtkYA8WPu8wVGCXbN8wwh/StOocszxb" +
            "g+iLvGeh8CYSRqg6QN3S/02etH3o8H4e7Z0PZwIDAQABoyMwITAPBgNVHRMBAf8E" +
            "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCtWdirSsmt" +
            "+CBBCNn6ZnbU3QqQfiiQIomjenNEHESJgaS/+PvPE5i3xWFXsunTHLW321/Km16I" +
            "7+ZvT8Su1cqHg79NAT8QB0yke1saKSy2C0Pic4HwrNqVBWFNSxMU0hQzpx/ZXDbZ" +
            "DqIXAp5EfyRYBy2ul+jm6Rot6aFgzuopKg==");

        internal static readonly byte[] certC = Base64.Decode(
            "MIICtTCCAh6gAwIBAgIBAjANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50" +
            "ZXIxMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX" +
            "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq" +
            "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ0Mzla" +
            "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjIxCzAJBgNVBAYTAkNI" +
            "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw" +
            "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A" +
            "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0rLr6" +
            "f2/ONeJzTb0q9M/NNX+MnAFMSqiQGVBkT76u5nOH4KLkpHXkzI82JI7GuQMzoT3a" +
            "+RP1hO6FneO92ms2soC6xiOFb4EC69Dfhh87Nww5O35JxVF0bzmbmIAWd6P/7zGh" +
            "nd2S4tKkaZcubps+C0j9Fgi0hipVicAOUVVoDQIDAQABoyMwITAPBgNVHRMBAf8E" +
            "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCLPvc1IMA4" +
            "YP+PmnEldyUoRWRnvPWjBGeu0WheBP7fdcnGBf93Nmc5j68ZN+eTZ5VMuZ99YdvH" +
            "CXGNX6oodONLU//LlFKdLl5xjLAS5X9p1RbOEGytnalqeiEpjk4+C/7rIBG1kllO" +
            "dItmI6LlEMV09Hkpg6ZRAUmRkb8KrM4X7A==");

        internal static readonly byte[] certD = Base64.Decode(
            "MIICtTCCAh6gAwIBAgIBBjANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50" +
            "ZXIzMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX" +
            "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq" +
            "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ5NTNa" +
            "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjExCzAJBgNVBAYTAkNI" +
            "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw" +
            "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A" +
            "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCae3TP" +
            "jIVKeASqvNabaiUHAMGUgFxB7L0yUsIj39azLcLtUj4S7XkDf7SMGtYV0JY1XNaQ" +
            "sHJAsnJivDZc50oiYvqDYfgFZx5+AsN5l5X5rjRzs/OX+Jo+k1OgsIyu6+mf9Kfb" +
            "5IdWOVB2EcOg4f9tPjLM8CIj9Pp7RbKLyqUUgwIDAQABoyMwITAPBgNVHRMBAf8E" +
            "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCgr9kUdWUT" +
            "Lt9UcztSzR3pnHRsyvS0E/z850OKQKS5/VxLEalpFvhj+3EcZ7Y6mFxaaS2B7vXg" +
            "2YWyqV1PRb6iF7/u9EXkpSTKGrJahwANirCa3V/HTUuPdCE2GITlnWI8h3eVA+xQ" +
            "D4LF0PXHOkXbwmhXRSb10lW1bSGkUxE9jg==");

        [Test]
        public void Basic()
        {
            X509CertificateParser cf = new X509CertificateParser();

            X509Certificate rootCert = cf.ReadCertificate(rootCertBin);
            X509Certificate interCert = cf.ReadCertificate(interCertBin);
            X509Certificate finalCert = cf.ReadCertificate(finalCertBin);

            //Testing CertPath generation from List
            var list = new List<X509Certificate>();
            list.Add(interCert);
            PkixCertPath certPath1 = new PkixCertPath(list);

            //Testing CertPath encoding as PkiPath
            byte[] encoded = certPath1.GetEncoded("PkiPath");

            //Testing CertPath generation from InputStream
            MemoryStream inStream = new MemoryStream(encoded, false);
            PkixCertPath certPath2 = new PkixCertPath(inStream, "PkiPath");

            Assert.AreEqual(certPath1, certPath2, "CertPath differ after encoding and decoding.");

            encoded = certPath1.GetEncoded("PKCS7");

            //Testing CertPath generation from InputStream
            inStream = new MemoryStream(encoded, false);
            certPath2 = new PkixCertPath(inStream, "PKCS7");

            Assert.AreEqual(certPath1, certPath2, "CertPath differ after encoding and decoding.");

            encoded = certPath1.GetEncoded("PEM");

            //Testing CertPath generation from InputStream
            inStream = new MemoryStream(encoded, false);
            certPath2 = new PkixCertPath(inStream, "PEM");

            Assert.AreEqual(certPath1, certPath2, "CertPath differ after encoding and decoding.");

            //
            // empty list test
            //
            list = new List<X509Certificate>();

            PkixCertPath certPath = new PkixCertPath(list);

            Assert.AreEqual(0, certPath.Certificates.Count, "list wrong size.");
        }

        [Test]
        public void Exceptions()
        {
            byte[] enc = { (byte)0, (byte)2, (byte)3, (byte)4, (byte)5 };
            //MyCertPath mc = new MyCertPath(enc);
            MemoryStream os = new MemoryStream();
            MemoryStream ins;
            byte[] arr;

            // TODO Support serialization of cert paths?
            //ObjectOutputStream oos = new ObjectOutputStream(os);
            //oos.WriteObject(mc);
            //oos.Flush();
            //oos.Close();

            try
            {
                arr = os.ToArray();
                ins = new MemoryStream(arr, false);
                new PkixCertPath(ins);
            }
            catch (CertificateException)
            {
                // ignore okay
            }

            X509CertificateParser cf = new X509CertificateParser();
            var certCol = new List<X509Certificate>();

            certCol.Add(cf.ReadCertificate(certA));
            certCol.Add(cf.ReadCertificate(certB));
            certCol.Add(cf.ReadCertificate(certC));
            certCol.Add(cf.ReadCertificate(certD));

            PkixCertPathBuilder pathBuilder = new PkixCertPathBuilder();
            X509CertStoreSelector select = new X509CertStoreSelector();
            select.Subject = certCol[0].SubjectDN;

            var trustanchors = new HashSet<TrustAnchor>();
            trustanchors.Add(new TrustAnchor(cf.ReadCertificate(rootCertBin), null));

            var x509CertStore = CollectionUtilities.CreateStore(certCol);

            PkixBuilderParameters parameters = new PkixBuilderParameters(trustanchors, select);
            parameters.AddStoreCert(x509CertStore);

            try
            {
                PkixCertPathBuilderResult result = pathBuilder.Build(parameters);
                PkixCertPath path = result.CertPath;
                Assert.Fail("found cert path in circular set");
            }
            catch (PkixCertPathBuilderException)
            {
                // expected
            }
        }

        [Test]
        public void SortCerts()
        {
            var rootPair = TestUtilities.GenerateRsaKeyPair();
            var interPair = TestUtilities.GenerateRsaKeyPair();
            var endPair = TestUtilities.GenerateRsaKeyPair();

            X509Certificate root = TestUtilities.GenerateRootCert(rootPair);
            X509Certificate inter = TestUtilities.GenerateIntermediateCert(interPair.Public, rootPair.Private, root);
            X509Certificate end = TestUtilities.GenerateEndEntityCert(endPair.Public, interPair.Private, inter);

            // For every permutation of [end, inter, root] the X.509 BC CertificateFactory
            // must hand back end-entity first, then intermediate, then root (github #1269).
            // Pre-fix the SortCerts loops mutated the working list while iterating, so the
            // [end, root, inter] permutation in particular came back unsorted because both
            // end and inter were classified as end-entity candidates.
            X509Certificate[][] permutations = {
                new X509Certificate[]{ end, inter, root },
                new X509Certificate[]{ end, root, inter },
                new X509Certificate[]{ inter, end, root },
                new X509Certificate[]{ inter, root, end },
                new X509Certificate[]{ root, end, inter },
                new X509Certificate[]{ root, inter, end },
            };

            X509CertificateParser cf = new X509CertificateParser();

            for (int i = 0; i != permutations.Length; i++)
            {
                var permutation = permutations[i];
                var input = new List<X509Certificate>(permutation);
                var path = new PkixCertPath(input);
                var sorted = path.Certificates;

                if (sorted.Count != 3 || !sorted[0].Equals(end) || !sorted[1].Equals(inter) || !sorted[2].Equals(root))
                {
                    Assert.Fail("CertPath not sorted for permutation [" + permutation[0].SubjectDN + ", " +
                        permutation[1].SubjectDN + ", " + permutation[2].SubjectDN + "]: got " + sorted);
                }
            }
        }

        private class MyCertificate
            : X509Certificate
        {
            private readonly string type;
            private readonly byte[] encoding;

            public MyCertificate(string type, byte[] encoding)
                //: base(type)
            {
                this.type = type;

                // don't copy to allow null parameter in test
                this.encoding = encoding;
            }

            public override byte[] GetEncoded()
            {
                // do copy to force NPE in test
                return (byte[])encoding.Clone();
            }

            public override void Verify(AsymmetricKeyParameter publicKey)
            {
            }

            public override string ToString() => "[My test Certificate, type: " + type + "]";

            public override AsymmetricKeyParameter GetPublicKey()
            {
                throw new NotImplementedException();

                //return new PublicKey()
                //{
                //    public string getAlgorithm()
                //    {
                //        return "TEST";
                //    }
                
                //    public byte[] getEncoded()
                //    {
                //        return new byte[] { (byte)1, (byte)2, (byte)3 };
                //    }
                
                //    public string getFormat()
                //    {
                //        return "TEST_FORMAT";
                //    }
                //};
            }
        }

        //private class MyCertPath
        //    : PkixCertPath
        //{
        //    private readonly List<X509Certificate> certificates;
        //    private readonly List<string> encodingNames;
        //    private readonly byte[] encoding;

        //    public MyCertPath(byte[] encoding)
        //        : base("MyEncoding")
        //    {
        //        this.encoding = encoding;
        //        certificates = new List<X509Certificate>(){ new MyCertificate("MyEncoding", encoding) };
        //        encodingNames = new List<string>(){ "MyEncoding" };
        //    }

        //    public override IList<X509Certificate> Certificates => CollectionUtilities.ReadOnly(certificates);

        //    public override byte[] GetEncoded() => (byte[])encoding.Clone();

        //    public override byte[] GetEncoded(string encoding)
        //    {
        //        if (Type.Equals(encoding))
        //            return (byte[])this.encoding.Clone();

        //        throw new CertificateEncodingException("Encoding not supported: "
        //            + encoding);
        //    }

        //    public override IEnumerable<string> Encodings => CollectionUtilities.Proxy(encodingNames);
        //}
    }
}
