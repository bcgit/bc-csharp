using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tls.Tests
{
    public class TlsTestUtilities
    {
        internal static readonly byte[] RsaCertData = Base64.Decode(
            "MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2" +
            "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq" +
            "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA2MDIwNVoXDTEzMDIyNT" +
            "A2MDM0NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw" +
            "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG" +
            "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy" +
            "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCBSAwEgYDVR" +
            "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAHU55Ncz" +
            "eglREcTg54YLUlGWu2WOYWhit/iM1eeq8Kivro7q98eW52jTuMI3CI5ulqd0hYzshQKQaZ5GDzErMyM=");

        internal static readonly byte[] DudRsaCertData = Base64.Decode(
            "MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2" +
            "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq" +
            "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA1NDcyOFoXDTEzMDIyNT" +
            "A1NDkwOFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw" +
            "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG" +
            "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy" +
            "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR" +
            "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAJg55PBS" +
            "weg6obRUKF4FF6fCrWFi6oCYSQ99LWcAeupc5BofW5MstFMhCOaEucuGVqunwT5G7/DweazzCIrSzB0=");

        internal static bool EqualsIgnoreCase(string a, string b)
        {
            return ToUpperInvariant(a) == ToUpperInvariant(b);
        }

        internal static string ToUpperInvariant(string s)
        {
            return s.ToUpper(CultureInfo.InvariantCulture);
        }

        internal static string Fingerprint(X509CertificateStructure c)
        {
            byte[] der = c.GetEncoded();
            byte[] hash = Sha256DigestOf(der);
            byte[] hexBytes = Hex.Encode(hash);
            string hex = ToUpperInvariant(Encoding.ASCII.GetString(hexBytes));

            StringBuilder fp = new StringBuilder();
            int i = 0;
            fp.Append(hex.Substring(i, 2));
            while ((i += 2) < hex.Length)
            {
                fp.Append(':');
                fp.Append(hex.Substring(i, 2));
            }
            return fp.ToString();
        }

        internal static byte[] Sha256DigestOf(byte[] input)
        {
            return DigestUtilities.CalculateDigest("SHA256", input);
        }

        internal static string GetCACertResource(short signatureAlgorithm)
        {
            return "x509-ca-" + GetResourceName(signatureAlgorithm) + ".pem";
        }

        internal static string GetCACertResource(string eeCertResource)
        {
            if (eeCertResource.StartsWith("x509-client-"))
            {
                eeCertResource = eeCertResource.Substring("x509-client-".Length);
            }
            if (eeCertResource.StartsWith("x509-server-"))
            {
                eeCertResource = eeCertResource.Substring("x509-server-".Length);
            }
            if (eeCertResource.EndsWith(".pem"))
            {
                eeCertResource = eeCertResource.Substring(0, eeCertResource.Length - ".pem".Length);
            }

            if (EqualsIgnoreCase("dsa", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.dsa);
            }

            if (EqualsIgnoreCase("ecdh", eeCertResource)
                || EqualsIgnoreCase("ecdsa", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.ecdsa);
            }

            if (EqualsIgnoreCase("ed25519", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.ed25519);
            }

            if (EqualsIgnoreCase("ed448", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.ed448);
            }

            if (EqualsIgnoreCase("rsa", eeCertResource)
                || EqualsIgnoreCase("rsa-enc", eeCertResource)
                || EqualsIgnoreCase("rsa-sign", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.rsa);
            }

            if (EqualsIgnoreCase("rsa_pss_256", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.rsa_pss_pss_sha256);
            }
            if (EqualsIgnoreCase("rsa_pss_384", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.rsa_pss_pss_sha384);
            }
            if (EqualsIgnoreCase("rsa_pss_512", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.rsa_pss_pss_sha512);
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        internal static string GetResourceName(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
                return "rsa";
            case SignatureAlgorithm.dsa:
                return "dsa";
            case SignatureAlgorithm.ecdsa:
                return "ecdsa";
            case SignatureAlgorithm.ed25519:
                return "ed25519";
            case SignatureAlgorithm.ed448:
                return "ed448";
            case SignatureAlgorithm.rsa_pss_pss_sha256:
                return "rsa_pss_256";
            case SignatureAlgorithm.rsa_pss_pss_sha384:
                return "rsa_pss_384";
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return "rsa_pss_512";
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        internal static TlsCredentialedAgreement LoadAgreementCredentials(TlsContext context, string[] certResources,
            string keyResource)
        {
            TlsCrypto crypto = context.Crypto;
            Certificate certificate = LoadCertificateChain(context, certResources);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
            if (crypto is BcTlsCrypto)
            {
                AsymmetricKeyParameter privateKey = LoadBcPrivateKeyResource(keyResource);

                return new BcDefaultTlsCredentialedAgreement((BcTlsCrypto)crypto, certificate, privateKey);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        internal static TlsCredentialedDecryptor LoadEncryptionCredentials(TlsContext context, string[] certResources,
            string keyResource)
        {
            TlsCrypto crypto = context.Crypto;
            Certificate certificate = LoadCertificateChain(context, certResources);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
            if (crypto is BcTlsCrypto)
            {
                AsymmetricKeyParameter privateKey = LoadBcPrivateKeyResource(keyResource);

                return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)crypto, certificate, privateKey);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public static TlsCredentialedSigner LoadSignerCredentials(TlsCryptoParameters cryptoParams, TlsCrypto crypto,
            string[] certResources, string keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            Certificate certificate = LoadCertificateChain(cryptoParams.ServerVersion, crypto, certResources);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
            if (crypto is BcTlsCrypto)
            {
                AsymmetricKeyParameter privateKey = LoadBcPrivateKeyResource(keyResource);

                return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)crypto, privateKey, certificate, signatureAndHashAlgorithm);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        internal static TlsCredentialedSigner LoadSignerCredentials(TlsContext context, string[] certResources,
            string keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            TlsCrypto crypto = context.Crypto;
            TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);

            return LoadSignerCredentials(cryptoParams, crypto, certResources, keyResource, signatureAndHashAlgorithm);
        }

        internal static TlsCredentialedSigner LoadSignerCredentials(TlsContext context,
            IList<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, short signatureAlgorithm,
            string certResource, string keyResource)
        {
            if (supportedSignatureAlgorithms == null)
            {
                supportedSignatureAlgorithms = TlsUtilities.GetDefaultSignatureAlgorithms(signatureAlgorithm);
            }

            SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;

            foreach (SignatureAndHashAlgorithm alg in supportedSignatureAlgorithms)
            {
                if (alg.Signature == signatureAlgorithm)
                {
                    // Just grab the first one we find
                    signatureAndHashAlgorithm = alg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null)
                return null;

            return LoadSignerCredentials(context, new string[]{ certResource }, keyResource,
                signatureAndHashAlgorithm);
        }

        internal static TlsCredentialedSigner LoadSignerCredentialsServer(TlsContext context,
            IList<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, short signatureAlgorithm)
        {
            string sigName = GetResourceName(signatureAlgorithm);

            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
                sigName += "-sign";
                break;
            }

            string certResource = "x509-server-" + sigName + ".pem";
            string keyResource = "x509-server-key-" + sigName + ".pem";

            return LoadSignerCredentials(context, supportedSignatureAlgorithms, signatureAlgorithm, certResource,
                keyResource);
        }

        internal static Certificate LoadCertificateChain(ProtocolVersion protocolVersion, TlsCrypto crypto,
            string[] resources)
        {
            if (TlsUtilities.IsTlsV13(protocolVersion))
            {
                CertificateEntry[] certificateEntryList = new CertificateEntry[resources.Length];
                for (int i = 0; i < resources.Length; ++i)
                {
                    TlsCertificate certificate = LoadCertificateResource(crypto, resources[i]);

                    // TODO[tls13] Add possibility of specifying e.g. CertificateStatus 
                    IDictionary<int, byte[]> extensions = null;

                    certificateEntryList[i] = new CertificateEntry(certificate, extensions);
                }

                // TODO[tls13] Support for non-empty request context
                byte[] certificateRequestContext = TlsUtilities.EmptyBytes;

                return new Certificate(certificateRequestContext, certificateEntryList);
            }
            else
            {
                TlsCertificate[] chain = new TlsCertificate[resources.Length];
                for (int i = 0; i < resources.Length; ++i)
                {
                    chain[i] = LoadCertificateResource(crypto, resources[i]);
                }
                return new Certificate(chain);
            }
        }

        internal static Certificate LoadCertificateChain(TlsContext context, string[] resources)
        {
            return LoadCertificateChain(context.ServerVersion, context.Crypto, resources);
        }

        internal static X509CertificateStructure LoadBcCertificateResource(string resource)
        {
            PemObject pem = LoadPemResource(resource);
            if (pem.Type.EndsWith("CERTIFICATE"))
            {
                return X509CertificateStructure.GetInstance(pem.Content);
            }
            throw new ArgumentException("doesn't specify a valid certificate", "resource");
        }

        internal static TlsCertificate LoadCertificateResource(TlsCrypto crypto, string resource)
        {
            PemObject pem = LoadPemResource(resource);
            if (pem.Type.EndsWith("CERTIFICATE"))
            {
                return crypto.CreateCertificate(pem.Content);
            }
            throw new ArgumentException("doesn't specify a valid certificate", "resource");
        }

        internal static AsymmetricKeyParameter LoadBcPrivateKeyResource(string resource)
        {
            PemObject pem = LoadPemResource(resource);
            if (pem.Type.Equals("PRIVATE KEY"))
            {
                return PrivateKeyFactory.CreateKey(pem.Content);
            }
            if (pem.Type.Equals("ENCRYPTED PRIVATE KEY"))
            {
                throw new NotSupportedException("Encrypted PKCS#8 keys not supported");
            }
            if (pem.Type.Equals("RSA PRIVATE KEY"))
            {
                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(pem.Content);
                return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
                    rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                    rsa.Exponent2, rsa.Coefficient);
            }
            if (pem.Type.Equals("EC PRIVATE KEY"))
            {
                ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(pem.Content);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey,
                    pKey.GetParameters());
                PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
                return PrivateKeyFactory.CreateKey(privInfo);
            }
            throw new ArgumentException("doesn't specify a valid private key", "resource");
        }

        internal static PemObject LoadPemResource(string resource)
           
        {
            Stream s = SimpleTest.GetTestDataAsStream("tls." + resource);
            PemReader p = new PemReader(new StreamReader(s));
            PemObject o = p.ReadPemObject();
            p.Reader.Close();
            return o;
        }

        internal static bool AreSameCertificate(TlsCrypto crypto, TlsCertificate cert, string resource)
        {
            // TODO Cache test resources?
            return AreSameCertificate(cert, LoadCertificateResource(crypto, resource));
        }

        internal static bool AreSameCertificate(TlsCertificate a, TlsCertificate b)
        {
            // TODO[tls-ops] Support equals on TlsCertificate?
            return Arrays.AreEqual(a.GetEncoded(), b.GetEncoded());
        }

        internal static TlsCertificate[] GetTrustedCertPath(TlsCrypto crypto, TlsCertificate cert, string[] resources)
        {
            foreach (string eeCertResource in resources)
            {
                TlsCertificate eeCert = LoadCertificateResource(crypto, eeCertResource);
                if (AreSameCertificate(cert, eeCert))
                {
                    string caCertResource = GetCACertResource(eeCertResource);
                    TlsCertificate caCert = LoadCertificateResource(crypto, caCertResource);
                    if (null != caCert)
                    {
                        return new TlsCertificate[]{ eeCert, caCert };
                    }
                }
            }
            return null;
        }
    }
}
