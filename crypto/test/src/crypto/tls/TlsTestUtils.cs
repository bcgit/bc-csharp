using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Security;
using System.IO;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Reflection;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Tls.Test
{
    public class TlsTestUtils
    {
        public static readonly byte[] rsaCertData = Base64
            .Decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2"
                + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq"
                + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA2MDIwNVoXDTEzMDIyNT"
                + "A2MDM0NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
                + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG"
                + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy"
                + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCBSAwEgYDVR"
                + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAHU55Ncz"
                + "eglREcTg54YLUlGWu2WOYWhit/iM1eeq8Kivro7q98eW52jTuMI3CI5ulqd0hYzshQKQaZ5GDzErMyM=");

        public static readonly byte[] dudRsaCertData = Base64
                .Decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2"
                + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq"
                + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA1NDcyOFoXDTEzMDIyNT"
                + "A1NDkwOFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
                + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG"
                + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy"
                + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR"
                + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAJg55PBS"
                + "weg6obRUKF4FF6fCrWFi6oCYSQ99LWcAeupc5BofW5MstFMhCOaEucuGVqunwT5G7/DweazzCIrSzB0=");

        public static string fingerprint(X509CertificateStructure c)
        {
            byte[] der = c.GetEncoded();
            byte[] sha1 = sha256DigestOf(der);
            byte[] hexBytes = Hex.Encode(sha1);
            string hex = Encoding.ASCII.GetString(hexBytes).ToUpper();

            StringBuilder fp = new StringBuilder();
            int i = 0;
            fp.Append(hex.Substring(i, 2));
            while ((i += 2) <= hex.Length)
            {
                fp.Append(':');
                fp.Append(hex.Substring(i - 2, 2));
            }
            return fp.ToString();
        }

        public static byte[] sha256DigestOf(byte[] input)
        {
            Sha256Digest d = new Sha256Digest();
            d.BlockUpdate(input, 0, input.Length);
            byte[] result = new byte[d.GetDigestSize()];
            d.DoFinal(result, 0);
            return result;
        }

        public static TlsAgreementCredentials loadAgreementCredentials(TlsContext context,
                                                                string[] certResources, string keyResource)
        {

            Certificate certificate = loadCertificateChain(certResources);
            AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);

            return new DefaultTlsAgreementCredentials(certificate, privateKey);
        }

        public static TlsEncryptionCredentials loadEncryptionCredentials(TlsContext context,
                                                                  string[] certResources, string keyResource)
        {

            Certificate certificate = loadCertificateChain(certResources);
            AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);

            return new DefaultTlsEncryptionCredentials(context, certificate, privateKey);
        }

        public static TlsSignerCredentials loadSignerCredentials(TlsContext context, string[] certResources,
                                                          string keyResource)
        {

            var certificate = loadCertificateChain(certResources);
            AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);
            return new DefaultTlsSignerCredentials(context, certificate, privateKey);
        }

        public static Certificate loadCertificateChain(string[] resources)
        {

            X509CertificateStructure[] chain = new X509CertificateStructure[resources.Length];
            for (int i = 0; i < resources.Length; ++i)
            {
                chain[i] = loadCertificateResource(resources[i]);
            }
            return new Certificate(chain);
        }

        public static X509CertificateStructure loadCertificateResource(string resource)
        {

            PemObject pem = loadPemResource(resource);
            if (pem.Type.EndsWith("CERTIFICATE"))
            {
                return X509CertificateStructure.GetInstance(pem.Content);
            }
            throw new ArgumentException("'resource' doesn't specify a valid certificate");
        }

        public static AsymmetricKeyParameter loadPrivateKeyResource(string resource)
        {

            PemObject pem = loadPemResource(resource);
            if (pem.Type.EndsWith("RSA PRIVATE KEY"))
            {
                var asn1 = Asn1Sequence.GetInstance(pem.Content);

                RsaPrivateKeyStructure rsa = new RsaPrivateKeyStructure(asn1);
                return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
                    rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                    rsa.Exponent2, rsa.Coefficient);
            }
            if (pem.Type.EndsWith("PRIVATE KEY"))
            {
                return PrivateKeyFactory.CreateKey(pem.Content);
            }
            throw new ArgumentException("'resource' doesn't specify a valid private key");
        }

        private static PemObject loadPemResource(string resource)
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
            {
                PemReader p = new PemReader(new StreamReader(stream));
                PemObject o = p.ReadPemObject();
                return o;
            }
        }        
    }
}
