using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.IO.Tests
{
    [TestFixture]
    public class PemReaderTest
    {

        [Test]
        public void TestMalformedInput()
        {
            string raw = "-----BEGIN CERTIFICATE REQUEST----- MIIBkTCB+wIBADAUMRIwEAYDVQQDDAlUZXN0MlNBTnMwgZ8wDQYJKoZIhvcNAQEB BQADgY0AMIGJAoGBAPPPH7W8LqBMCwSu/MsmCeSCfBzMEp4k+aZmeKw8EQD1R3FK WtPy/LcaUyQhyIeNPFAH8JEz0dJRJjleFL8G5pv7c2YXjBmIfbF/W2eETBIohMDP pWOqKYiT1mqzw25rP1VuXGXaSfN22RReomUd9O2GuEkaqz5x5iTRD6aLmDoJAgMB AAGgPjA8BgkqhkiG9w0BCQ4xLzAtMCsGA1UdEQQkMCKCD3NhbjEudGVzdC5sb2Nh bIIPc2FuMi50ZXN0LmxvY2FsMA0GCSqGSIb3DQEBCwUAA4GBAOacp+9s7/jpmSTA ORvx4nsDwBsY4VLeuPUc2gYmHqfVgrCCSHKPQtQge0P5atudbo+q8Fn+/5JnJR6/ JaooICY3M+/QVrvzvV30i5W8aEIERfXsEIcFyVxv24p6SbrGAcSjwpqvgAf0z82F D3f1qdFATb9HAFsuD/J0HexTFDvB -----END CERTIFICATE REQUEST-----";

            PemReader pemReader = new PemReader(new StringReader(raw));
            var item = pemReader.ReadPemObject();

            var pkcs10 = Pkcs10CertificationRequest.GetInstance(Asn1Sequence.GetInstance(item.Content));
            var subject = pkcs10.GetCertificationRequestInfo().Subject.ToString();

            Assert.AreEqual("CERTIFICATE REQUEST", item.Type);
            Assert.AreEqual("CN=Test2SANs", subject);
        }



        [Test]
        public void TestSaneInput()
        {

            String test = "Certificate:\n" +
         "    Data:\n" +
         "        Version: 3 (0x2)\n" +
         "        Serial Number: 865 (0x361)\n" +
         "    Signature Algorithm: ecdsa-with-SHA1\n" +
         "        Issuer: CN=estExampleCA\n" +
         "        Validity\n" +
         "            Not Before: Sep 29 12:41:31 2014 GMT\n" +
         "            Not After : Dec 16 12:41:31 2022 GMT\n" +
         "        Subject: CN=*.cisco.com\n" +
         "        Subject Public Key Info:\n" +
         "            Public Key Algorithm: rsaEncryption\n" +
         "                Public-Key: (1024 bit)\n" +
         "                Modulus:\n" +
         "                    00:b7:08:e6:18:f2:32:d7:07:44:4b:f3:b1:83:01:\n" +
         "                    59:f8:bc:ec:26:71:92:9a:53:70:f2:c0:be:2a:d6:\n" +
         "                    26:6f:45:11:86:d7:ee:37:9d:d3:2f:22:b2:8b:9b:\n" +
         "                    c5:96:00:36:73:97:c3:4c:f2:7a:0b:2c:e0:cc:d9:\n" +
         "                    f0:ec:ba:1b:75:8c:66:b1:86:10:fd:be:df:6b:67:\n" +
         "                    9c:0e:6b:2a:0e:d0:80:a8:dc:7a:d4:df:6e:79:28:\n" +
         "                    a7:60:1a:11:b7:ae:40:94:bb:b4:11:ed:1b:6f:a7:\n" +
         "                    91:ae:33:ec:bf:9c:30:f3:dc:91:2c:b4:3e:8c:c9:\n" +
         "                    bd:f1:d1:aa:f6:c2:1d:6a:cd\n" +
         "                Exponent: 65537 (0x10001)\n" +
         "        X509v3 extensions:\n" +
         "            X509v3 Basic Constraints: \n" +
         "                CA:FALSE\n" +
         "            X509v3 Key Usage: \n" +
         "                Digital Signature, Non Repudiation, Key Encipherment\n" +
         "    Signature Algorithm: ecdsa-with-SHA1\n" +
         "         30:44:02:20:76:4f:3a:6c:b4:99:cb:1e:37:f4:0d:6e:e1:74:\n" +
         "         4b:99:bb:f5:c4:b6:3d:c1:61:df:8c:d7:1f:9f:e7:d3:64:d6:\n" +
         "         02:20:64:38:8f:6f:32:37:2b:7d:cf:28:93:e5:e6:e7:70:c5:\n" +
         "         a9:12:04:b0:4b:a5:29:7b:23:df:85:f2:18:44:8b:d2\n" +
         "-----BEGIN CERTIFICATE-----\n" +
         "MIIBezCCASOgAwIBAgICA2EwCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFt\n" +
         "cGxlQ0EwHhcNMTQwOTI5MTI0MTMxWhcNMjIxMjE2MTI0MTMxWjAWMRQwEgYDVQQD\n" +
         "DAsqLmNpc2NvLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtwjmGPIy\n" +
         "1wdES/OxgwFZ+LzsJnGSmlNw8sC+KtYmb0URhtfuN53TLyKyi5vFlgA2c5fDTPJ6\n" +
         "CyzgzNnw7LobdYxmsYYQ/b7fa2ecDmsqDtCAqNx61N9ueSinYBoRt65AlLu0Ee0b\n" +
         "b6eRrjPsv5ww89yRLLQ+jMm98dGq9sIdas0CAwEAAaMaMBgwCQYDVR0TBAIwADAL\n" +
         "BgNVHQ8EBAMCBeAwCQYHKoZIzj0EAQNHADBEAiB2TzpstJnLHjf0DW7hdEuZu/XE\n" +
         "tj3BYd+M1x+f59Nk1gIgZDiPbzI3K33PKJPl5udwxakSBLBLpSl7I9+F8hhEi9I=\n" +
         "-----END CERTIFICATE-----\n";

            PemReader pemReader = new PemReader(new StringReader(test));
            var item = pemReader.ReadPemObject();
            Assert.AreEqual("CERTIFICATE", item.Type);
            X509CertificateStructure cert = X509CertificateStructure.GetInstance(Asn1Sequence.GetInstance(item.Content));
            Assert.AreEqual("CN=estExampleCA", cert.Issuer.ToString());
        }


        [Test]
        public void TestWithHeaders()
        {
            String hdr = "Proc-Type: 4,CRL\n";
            String hdr2 = "CRL: CRL Header\n";
            String hdr3 = "Originator-Certificate: originator certificate\n";
            String hdr4 = "CRL: crl header\n";
            String hdr5 = "Originator-Certificate: next originator certificate\n";

            String test = "-----BEGIN CERTIFICATE-----\n" + hdr + hdr2 + "    \t\r\0" + hdr3 + hdr4 + hdr5 +
         "MIIBezCCASOgAwIBAgICA2EwCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFt\n" +
         "cGxlQ0EwHhcNMTQwOTI5MTI0MTMxWhcNMjIxMjE2MTI0MTMxWjAWMRQwEgYDVQQD\n" +
         "DAsqLmNpc2NvLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtwjmGPIy\n" +
         "1wdES/OxgwFZ+LzsJnGSmlNw8sC+KtYmb0URhtfuN53TLyKyi5vFlgA2c5fDTPJ6\n" +
         "CyzgzNnw7LobdYxmsYYQ/b7fa2ecDmsqDtCAqNx61N9ueSinYBoRt65AlLu0Ee0b\n" +
         "b6eRrjPsv5ww89yRLLQ+jMm98dGq9sIdas0CAwEAAaMaMBgwCQYDVR0TBAIwADAL\n" +
         "BgNVHQ8EBAMCBeAwCQYHKoZIzj0EAQNHADBEAiB2TzpstJnLHjf0DW7hdEuZu/XE\n" +
         "tj3BYd+M1x+f59Nk1gIgZDiPbzI3K33PKJPl5udwxakSBLBLpSl7I9+F8hhEi9I=\n" +
         "-----END CERTIFICATE-----\n";

            PemReader pemReader = new PemReader(new StringReader(test));
            var item = pemReader.ReadPemObject();
            Assert.AreEqual("CERTIFICATE", item.Type);
            X509CertificateStructure cert = X509CertificateStructure.GetInstance(Asn1Sequence.GetInstance(item.Content));
            Assert.AreEqual("CN=estExampleCA", cert.Issuer.ToString());


            int t = 0;
            foreach(string[] items in new String[][] { 
                new string[] { "Proc-Type", "4,CRL" },
                new string[] { "CRL", "CRL Header" },
                new string[] { "Originator-Certificate", "originator certificate" },
                new string[] { "CRL", "crl header" },
                new string[] { "Originator-Certificate", "next originator certificate" },

            })
            {
                Assert.AreEqual(items[0], ((PemHeader)item.Headers[t]).Name);
                Assert.AreEqual(items[1], ((PemHeader)item.Headers[t]).Value);
                t++;
            }

        }

        [Test]
        public void TestNoWhiteSpace()
        {
           

            String test = "-----BEGIN CERTIFICATE-----"+ 
         "MIIBezCCASOgAwIBAgICA2EwCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFt" +
         "cGxlQ0EwHhcNMTQwOTI5MTI0MTMxWhcNMjIxMjE2MTI0MTMxWjAWMRQwEgYDVQQD" +
         "DAsqLmNpc2NvLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtwjmGPIy" +
         "1wdES/OxgwFZ+LzsJnGSmlNw8sC+KtYmb0URhtfuN53TLyKyi5vFlgA2c5fDTPJ6" +
         "CyzgzNnw7LobdYxmsYYQ/b7fa2ecDmsqDtCAqNx61N9ueSinYBoRt65AlLu0Ee0b" +
         "b6eRrjPsv5ww89yRLLQ+jMm98dGq9sIdas0CAwEAAaMaMBgwCQYDVR0TBAIwADAL" +
         "BgNVHQ8EBAMCBeAwCQYHKoZIzj0EAQNHADBEAiB2TzpstJnLHjf0DW7hdEuZu/XE" +
         "tj3BYd+M1x+f59Nk1gIgZDiPbzI3K33PKJPl5udwxakSBLBLpSl7I9+F8hhEi9I=" +
         "-----END CERTIFICATE-----";

            PemReader pemReader = new PemReader(new StringReader(test));
            var item = pemReader.ReadPemObject();
            Assert.AreEqual("CERTIFICATE", item.Type);
            X509CertificateStructure cert = X509CertificateStructure.GetInstance(Asn1Sequence.GetInstance(item.Content));
            Assert.AreEqual("CN=estExampleCA", cert.Issuer.ToString());
        }
  
    }
}
