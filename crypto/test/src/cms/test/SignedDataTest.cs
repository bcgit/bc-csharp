using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cert.Tests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
    [Parallelizable(ParallelScope.All)]
    public class SignedDataTest
    {
        private const string OrigDN = "O=Bouncy Castle, C=AU";
        private static AsymmetricCipherKeyPair origKP;
        private static X509Certificate origCert;

        private const string SignDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
        private static AsymmetricCipherKeyPair signKP;
        private static X509Certificate signCert;

        private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
        //private static AsymmetricCipherKeyPair reciKP;
        //private static X509Certificate reciCert;

        private static X509Crl signCrl;

        private static AsymmetricCipherKeyPair signGostKP;
        private static X509Certificate signGostCert;

        private static AsymmetricCipherKeyPair signDsaKP;
        private static X509Certificate signDsaCert;

        private static AsymmetricCipherKeyPair signECGostKP;
        private static X509Certificate signECGostCert;

        private static AsymmetricCipherKeyPair signECDsaKP;
        private static X509Certificate signECDsaCert;

        private static AsymmetricCipherKeyPair signEd25519KP;
        private static X509Certificate signEd25519Cert;

        private static AsymmetricCipherKeyPair signEd448KP;
        private static X509Certificate signEd448Cert;

        private static AsymmetricCipherKeyPair signMLDsa44KP;
        private static X509Certificate signMLDsa44Cert;

        private static AsymmetricCipherKeyPair signMLDsa65KP;
        private static X509Certificate signMLDsa65Cert;

        private static AsymmetricCipherKeyPair signMLDsa87KP;
        private static X509Certificate signMLDsa87Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Sha2_128f_KP;
        private static X509Certificate signSlhDsa_Sha2_128f_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Sha2_128s_KP;
        private static X509Certificate signSlhDsa_Sha2_128s_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Sha2_192f_KP;
        private static X509Certificate signSlhDsa_Sha2_192f_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Sha2_192s_KP;
        private static X509Certificate signSlhDsa_Sha2_192s_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Sha2_256f_KP;
        private static X509Certificate signSlhDsa_Sha2_256f_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Sha2_256s_KP;
        private static X509Certificate signSlhDsa_Sha2_256s_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Shake_128f_KP;
        private static X509Certificate signSlhDsa_Shake_128f_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Shake_128s_KP;
        private static X509Certificate signSlhDsa_Shake_128s_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Shake_192f_KP;
        private static X509Certificate signSlhDsa_Shake_192f_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Shake_192s_KP;
        private static X509Certificate signSlhDsa_Shake_192s_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Shake_256f_KP;
        private static X509Certificate signSlhDsa_Shake_256f_Cert;

        private static AsymmetricCipherKeyPair signSlhDsa_Shake_256s_KP;
        private static X509Certificate signSlhDsa_Shake_256s_Cert;

        private static AsymmetricCipherKeyPair OrigKP => CmsTestUtil.InitKP(ref origKP, CmsTestUtil.MakeKeyPair);

        //private static AsymmetricCipherKeyPair ReciKP => CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair SignKP => CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair SignDsaKP =>
            CmsTestUtil.InitKP(ref signDsaKP, CmsTestUtil.MakeDsaKeyPair);

        private static AsymmetricCipherKeyPair SignECDsaKP =>
            CmsTestUtil.InitKP(ref signECDsaKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair SignECGostKP =>
            CmsTestUtil.InitKP(ref signECGostKP, CmsTestUtil.MakeECGostKeyPair);

        private static AsymmetricCipherKeyPair SignGostKP =>
            CmsTestUtil.InitKP(ref signGostKP, CmsTestUtil.MakeGostKeyPair);

        private static AsymmetricCipherKeyPair SignEd25519KP =>
            CmsTestUtil.InitKP(ref signEd25519KP, CmsTestUtil.MakeEd25519KeyPair);

        private static AsymmetricCipherKeyPair SignEd448KP =>
            CmsTestUtil.InitKP(ref signEd448KP, CmsTestUtil.MakeEd448KeyPair);

        private static AsymmetricCipherKeyPair SignMLDsa44KP =>
            CmsTestUtil.InitKP(ref signMLDsa44KP, CmsTestUtil.MakeMLDsa44KeyPair);

        private static AsymmetricCipherKeyPair SignMLDsa65KP =>
            CmsTestUtil.InitKP(ref signMLDsa65KP, CmsTestUtil.MakeMLDsa65KeyPair);

        private static AsymmetricCipherKeyPair SignMLDsa87KP =>
            CmsTestUtil.InitKP(ref signMLDsa87KP, CmsTestUtil.MakeMLDsa87KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Sha2_128f_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Sha2_128f_KP, CmsTestUtil.MakeSlhDsa_Sha2_128f_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Sha2_128s_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Sha2_128s_KP, CmsTestUtil.MakeSlhDsa_Sha2_128s_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Sha2_192f_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Sha2_192f_KP, CmsTestUtil.MakeSlhDsa_Sha2_192f_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Sha2_192s_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Sha2_192s_KP, CmsTestUtil.MakeSlhDsa_Sha2_192s_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Sha2_256f_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Sha2_256f_KP, CmsTestUtil.MakeSlhDsa_Sha2_256f_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Sha2_256s_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Sha2_256s_KP, CmsTestUtil.MakeSlhDsa_Sha2_256s_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Shake_128f_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Shake_128f_KP, CmsTestUtil.MakeSlhDsa_Shake_128f_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Shake_128s_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Shake_128s_KP, CmsTestUtil.MakeSlhDsa_Shake_128s_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Shake_192f_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Shake_192f_KP, CmsTestUtil.MakeSlhDsa_Shake_192f_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Shake_192s_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Shake_192s_KP, CmsTestUtil.MakeSlhDsa_Shake_192s_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Shake_256f_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Shake_256f_KP, CmsTestUtil.MakeSlhDsa_Shake_256f_KeyPair);

        private static AsymmetricCipherKeyPair SignSlhDsa_Shake_256s_KP =>
            CmsTestUtil.InitKP(ref signSlhDsa_Shake_256s_KP, CmsTestUtil.MakeSlhDsa_Shake_256s_KeyPair);

        private static X509Certificate OrigCert => CmsTestUtil.InitCertificate(ref origCert,
            () => CmsTestUtil.MakeCertificate(OrigKP, OrigDN, OrigKP, OrigDN));

        //private static X509Certificate ReciCert => CmsTestUtil.InitCertificate(ref reciCert,
        //    () => CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN));

        private static X509Certificate SignCert => CmsTestUtil.InitCertificate(ref signCert,
            () => CmsTestUtil.MakeCertificate(SignKP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignDsaCert => CmsTestUtil.InitCertificate(ref signDsaCert,
            () => CmsTestUtil.MakeCertificate(SignDsaKP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignECDsaCert => CmsTestUtil.InitCertificate(ref signECDsaCert,
            () => CmsTestUtil.MakeCertificate(SignECDsaKP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignECGostCert => CmsTestUtil.InitCertificate(ref signECGostCert,
            () => CmsTestUtil.MakeCertificate(SignECGostKP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignGostCert => CmsTestUtil.InitCertificate(ref signGostCert,
            () => CmsTestUtil.MakeCertificate(SignGostKP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignEd25519Cert => CmsTestUtil.InitCertificate(ref signEd25519Cert,
            () => CmsTestUtil.MakeCertificate(SignEd25519KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignEd448Cert => CmsTestUtil.InitCertificate(ref signEd448Cert,
            () => CmsTestUtil.MakeCertificate(SignEd448KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignMLDsa44Cert => CmsTestUtil.InitCertificate(ref signMLDsa44Cert,
            () => CmsTestUtil.MakeCertificate(SignMLDsa44KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignMLDsa65Cert => CmsTestUtil.InitCertificate(ref signMLDsa65Cert,
            () => CmsTestUtil.MakeCertificate(SignMLDsa65KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignMLDsa87Cert => CmsTestUtil.InitCertificate(ref signMLDsa87Cert,
            () => CmsTestUtil.MakeCertificate(SignMLDsa87KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Sha2_128f_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Sha2_128f_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Sha2_128f_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Sha2_128s_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Sha2_128s_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Sha2_128s_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Sha2_192f_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Sha2_192f_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Sha2_192f_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Sha2_192s_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Sha2_192s_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Sha2_192s_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Sha2_256f_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Sha2_256f_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Sha2_256f_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Sha2_256s_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Sha2_256s_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Sha2_256s_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Shake_128f_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Shake_128f_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Shake_128f_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Shake_128s_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Shake_128s_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Shake_128s_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Shake_192f_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Shake_192f_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Shake_192f_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Shake_192s_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Shake_192s_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Shake_192s_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Shake_256f_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Shake_256f_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Shake_256f_KP, SignDN, OrigKP, OrigDN));

        private static X509Certificate SignSlhDsa_Shake_256s_Cert => CmsTestUtil.InitCertificate(ref signSlhDsa_Shake_256s_Cert,
            () => CmsTestUtil.MakeCertificate(SignSlhDsa_Shake_256s_KP, SignDN, OrigKP, OrigDN));

        private static X509Crl SignCrl => CmsTestUtil.InitCrl(ref signCrl, () => CmsTestUtil.MakeCrl(SignKP));

        private static readonly HashSet<DerObjectIdentifier> NoParams = new HashSet<DerObjectIdentifier>();

        private static readonly byte[] disorderedMessage = Base64.Decode(
            "SU9fc3RkaW5fdXNlZABfX2xpYmNfc3RhcnRfbWFpbgBnZXRob3N0aWQAX19n" +
            "bW9uX3M=");

        private static readonly byte[] disorderedSet = Base64.Decode(
            "MIIYXQYJKoZIhvcNAQcCoIIYTjCCGEoCAQExCzAJBgUrDgMCGgUAMAsGCSqG"
            + "SIb3DQEHAaCCFqswggJUMIIBwKADAgECAgMMg6wwCgYGKyQDAwECBQAwbzEL"
            + "MAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbI"
            + "dXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwEx"
            + "MBEGA1UEAxQKNFItQ0EgMTpQTjAiGA8yMDAwMDMyMjA5NDM1MFoYDzIwMDQw"
            + "MTIxMTYwNDUzWjBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1"
            + "bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEh"
            + "MAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1DQSAxOlBOMIGhMA0GCSqGSIb3"
            + "DQEBAQUAA4GPADCBiwKBgQCKHkFTJx8GmoqFTxEOxpK9XkC3NZ5dBEKiUv0I"
            + "fe3QMqeGMoCUnyJxwW0k2/53duHxtv2yHSZpFKjrjvE/uGwdOMqBMTjMzkFg"
            + "19e9JPv061wyADOucOIaNAgha/zFt9XUyrHF21knKCvDNExv2MYIAagkTKaj"
            + "LMAw0bu1J0FadQIFAMAAAAEwCgYGKyQDAwECBQADgYEAgFauXpoTLh3Z3pT/"
            + "3bhgrxO/2gKGZopWGSWSJPNwq/U3x2EuctOJurj+y2inTcJjespThflpN+7Q"
            + "nvsUhXU+jL2MtPlObU0GmLvWbi47cBShJ7KElcZAaxgWMBzdRGqTOdtMv+ev"
            + "2t4igGF/q71xf6J2c3pTLWr6P8s6tzLfOCMwggJDMIIBr6ADAgECAgQAuzyu"
            + "MAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGll"
            + "cnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0"
            + "MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE4wIhgPMjAwMTA4"
            + "MjAwODA4MjBaGA8yMDA1MDgyMDA4MDgyMFowSzELMAkGA1UEBhMCREUxEjAQ"
            + "BgNVBAoUCVNpZ250cnVzdDEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFDQSBT"
            + "SUdOVFJVU1QgMTpQTjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAhV12"
            + "N2WhlR6f+3CXP57GrBM9la5Vnsu2b92zv5MZqQOPeEsYbZqDCFkYg1bSwsDE"
            + "XsGVQqXdQNAGUaapr/EUVVN+hNZ07GcmC1sPeQECgUkxDYjGi4ihbvzxlahj"
            + "L4nX+UTzJVBfJwXoIvJ+lMHOSpnOLIuEL3SRhBItvRECxN0CAwEAAaMSMBAw"
            + "DgYDVR0PAQH/BAQDAgEGMAoGBiskAwMBAgUAA4GBACDc9Pc6X8sK1cerphiV"
            + "LfFv4kpZb9ev4WPy/C6987Qw1SOTElhZAmxaJQBqmDHWlQ63wj1DEqswk7hG"
            + "LrvQk/iX6KXIn8e64uit7kx6DHGRKNvNGofPjr1WelGeGW/T2ZJKgmPDjCkf"
            + "sIKt2c3gwa2pDn4mmCz/DStUIqcPDbqLMIICVTCCAcGgAwIBAgIEAJ16STAK"
            + "BgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1"
            + "bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEh"
            + "MAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1DQSAxOlBOMCIYDzIwMDEwMjAx"
            + "MTM0NDI1WhgPMjAwNTAzMjIwODU1NTFaMG8xCzAJBgNVBAYTAkRFMT0wOwYD"
            + "VQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0"
            + "aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjZSLUNhIDE6"
            + "UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGLAoGBAIOiqxUkzVyqnvthihnl"
            + "tsE5m1Xn5TZKeR/2MQPStc5hJ+V4yptEtIx+Fn5rOoqT5VEVWhcE35wdbPvg"
            + "JyQFn5msmhPQT/6XSGOlrWRoFummXN9lQzAjCj1sgTcmoLCVQ5s5WpCAOXFw"
            + "VWu16qndz3sPItn3jJ0F3Kh3w79NglvPAgUAwAAAATAKBgYrJAMDAQIFAAOB"
            + "gQBpSRdnDb6AcNVaXSmGo6+kVPIBhot1LzJOGaPyDNpGXxd7LV4tMBF1U7gr"
            + "4k1g9BO6YiMWvw9uiTZmn0CfV8+k4fWEuG/nmafRoGIuay2f+ILuT+C0rnp1"
            + "4FgMsEhuVNJJAmb12QV0PZII+UneyhAneZuQQzVUkTcVgYxogxdSOzCCAlUw"
            + "ggHBoAMCAQICBACdekowCgYGKyQDAwECBQAwbzELMAkGA1UEBhMCREUxPTA7"
            + "BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlr"
            + "YXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNlItQ2Eg"
            + "MTpQTjAiGA8yMDAxMDIwMTEzNDcwN1oYDzIwMDUwMzIyMDg1NTUxWjBvMQsw"
            + "CQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1"
            + "ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEhMAwGBwKCBgEKBxQTATEw"
            + "EQYDVQQDFAo1Ui1DQSAxOlBOMIGhMA0GCSqGSIb3DQEBAQUAA4GPADCBiwKB"
            + "gQCKHkFTJx8GmoqFTxEOxpK9XkC3NZ5dBEKiUv0Ife3QMqeGMoCUnyJxwW0k"
            + "2/53duHxtv2yHSZpFKjrjvE/uGwdOMqBMTjMzkFg19e9JPv061wyADOucOIa"
            + "NAgha/zFt9XUyrHF21knKCvDNExv2MYIAagkTKajLMAw0bu1J0FadQIFAMAA"
            + "AAEwCgYGKyQDAwECBQADgYEAV1yTi+2gyB7sUhn4PXmi/tmBxAfe5oBjDW8m"
            + "gxtfudxKGZ6l/FUPNcrSc5oqBYxKWtLmf3XX87LcblYsch617jtNTkMzhx9e"
            + "qxiD02ufcrxz2EVt0Akdqiz8mdVeqp3oLcNU/IttpSrcA91CAnoUXtDZYwb/"
            + "gdQ4FI9l3+qo/0UwggJVMIIBwaADAgECAgQAxIymMAoGBiskAwMBAgUAMG8x"
            + "CzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBm"
            + "yHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMB"
            + "MTARBgNVBAMUCjZSLUNhIDE6UE4wIhgPMjAwMTEwMTUxMzMxNThaGA8yMDA1"
            + "MDYwMTA5NTIxN1owbzELMAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVy"
            + "dW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3Qx"
            + "ITAMBgcCggYBCgcUEwExMBEGA1UEAxQKN1ItQ0EgMTpQTjCBoTANBgkqhkiG"
            + "9w0BAQEFAAOBjwAwgYsCgYEAiokD/j6lEP4FexF356OpU5teUpGGfUKjIrFX"
            + "BHc79G0TUzgVxqMoN1PWnWktQvKo8ETaugxLkP9/zfX3aAQzDW4Zki6x6GDq"
            + "fy09Agk+RJvhfbbIzRkV4sBBco0n73x7TfG/9NTgVr/96U+I+z/1j30aboM6"
            + "9OkLEhjxAr0/GbsCBQDAAAABMAoGBiskAwMBAgUAA4GBAHWRqRixt+EuqHhR"
            + "K1kIxKGZL2vZuakYV0R24Gv/0ZR52FE4ECr+I49o8FP1qiGSwnXB0SwjuH2S"
            + "iGiSJi+iH/MeY85IHwW1P5e+bOMvEOFhZhQXQixOD7totIoFtdyaj1XGYRef"
            + "0f2cPOjNJorXHGV8wuBk+/j++sxbd/Net3FtMIICVTCCAcGgAwIBAgIEAMSM"
            + "pzAKBgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxp"
            + "ZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9z"
            + "dDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAo3Ui1DQSAxOlBOMCIYDzIwMDEx"
            + "MDE1MTMzNDE0WhgPMjAwNTA2MDEwOTUyMTdaMG8xCzAJBgNVBAYTAkRFMT0w"
            + "OwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5p"
            + "a2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjZSLUNh"
            + "IDE6UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGLAoGBAIOiqxUkzVyqnvth"
            + "ihnltsE5m1Xn5TZKeR/2MQPStc5hJ+V4yptEtIx+Fn5rOoqT5VEVWhcE35wd"
            + "bPvgJyQFn5msmhPQT/6XSGOlrWRoFummXN9lQzAjCj1sgTcmoLCVQ5s5WpCA"
            + "OXFwVWu16qndz3sPItn3jJ0F3Kh3w79NglvPAgUAwAAAATAKBgYrJAMDAQIF"
            + "AAOBgQBi5W96UVDoNIRkCncqr1LLG9vF9SGBIkvFpLDIIbcvp+CXhlvsdCJl"
            + "0pt2QEPSDl4cmpOet+CxJTdTuMeBNXxhb7Dvualog69w/+K2JbPhZYxuVFZs"
            + "Zh5BkPn2FnbNu3YbJhE60aIkikr72J4XZsI5DxpZCGh6xyV/YPRdKSljFjCC"
            + "AlQwggHAoAMCAQICAwyDqzAKBgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9"
            + "MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVu"
            + "aWthdGlvbiB1bmQgUG9zdDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1D"
            + "QSAxOlBOMCIYDzIwMDAwMzIyMDk0MTI3WhgPMjAwNDAxMjExNjA0NTNaMG8x"
            + "CzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBm"
            + "yHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMB"
            + "MTARBgNVBAMUCjRSLUNBIDE6UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGL"
            + "AoGBAI8x26tmrFJanlm100B7KGlRemCD1R93PwdnG7svRyf5ZxOsdGrDszNg"
            + "xg6ouO8ZHQMT3NC2dH8TvO65Js+8bIyTm51azF6clEg0qeWNMKiiXbBXa+ph"
            + "hTkGbXiLYvACZ6/MTJMJ1lcrjpRF7BXtYeYMcEF6znD4pxOqrtbf9z5hAgUA"
            + "wAAAATAKBgYrJAMDAQIFAAOBgQB99BjSKlGPbMLQAgXlvA9jUsDNhpnVm3a1"
            + "YkfxSqS/dbQlYkbOKvCxkPGA9NBxisBM8l1zFynVjJoy++aysRmcnLY/sHaz"
            + "23BF2iU7WERy18H3lMBfYB6sXkfYiZtvQZcWaO48m73ZBySuiV3iXpb2wgs/"
            + "Cs20iqroAWxwq/W/9jCCAlMwggG/oAMCAQICBDsFZ9UwCgYGKyQDAwECBQAw"
            + "bzELMAkGA1UEBhMCREUxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNFItQ0Eg"
            + "MTpQTjE9MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxl"
            + "a29tbXVuaWthdGlvbiB1bmQgUG9zdDAiGA8xOTk5MDEyMTE3MzUzNFoYDzIw"
            + "MDQwMTIxMTYwMDAyWjBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxp"
            + "ZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9z"
            + "dDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAozUi1DQSAxOlBOMIGfMA0GCSqG"
            + "SIb3DQEBAQUAA4GNADCBiQKBgI4B557mbKQg/AqWBXNJhaT/6lwV93HUl4U8"
            + "u35udLq2+u9phns1WZkdM3gDfEpL002PeLfHr1ID/96dDYf04lAXQfombils"
            + "of1C1k32xOvxjlcrDOuPEMxz9/HDAQZA5MjmmYHAIulGI8Qg4Tc7ERRtg/hd"
            + "0QX0/zoOeXoDSEOBAgTAAAABMAoGBiskAwMBAgUAA4GBAIyzwfT3keHI/n2P"
            + "LrarRJv96mCohmDZNpUQdZTVjGu5VQjVJwk3hpagU0o/t/FkdzAjOdfEw8Ql"
            + "3WXhfIbNLv1YafMm2eWSdeYbLcbB5yJ1od+SYyf9+tm7cwfDAcr22jNRBqx8"
            + "wkWKtKDjWKkevaSdy99sAI8jebHtWz7jzydKMIID9TCCA16gAwIBAgICbMcw"
            + "DQYJKoZIhvcNAQEFBQAwSzELMAkGA1UEBhMCREUxEjAQBgNVBAoUCVNpZ250"
            + "cnVzdDEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFDQSBTSUdOVFJVU1QgMTpQ"
            + "TjAeFw0wNDA3MzAxMzAyNDZaFw0wNzA3MzAxMzAyNDZaMDwxETAPBgNVBAMM"
            + "CFlhY29tOlBOMQ4wDAYDVQRBDAVZYWNvbTELMAkGA1UEBhMCREUxCjAIBgNV"
            + "BAUTATEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIWzLlYLQApocXIp"
            + "pgCCpkkOUVLgcLYKeOd6/bXAnI2dTHQqT2bv7qzfUnYvOqiNgYdF13pOYtKg"
            + "XwXMTNFL4ZOI6GoBdNs9TQiZ7KEWnqnr2945HYx7UpgTBclbOK/wGHuCdcwO"
            + "x7juZs1ZQPFG0Lv8RoiV9s6HP7POqh1sO0P/AgMBAAGjggH1MIIB8TCBnAYD"
            + "VR0jBIGUMIGRgBQcZzNghfnXoXRm8h1+VITC5caNRqFzpHEwbzELMAkGA1UE"
            + "BhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVs"
            + "ZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UE"
            + "AxQKNVItQ0EgMTpQToIEALs8rjAdBgNVHQ4EFgQU2e5KAzkVuKaM9I5heXkz"
            + "bcAIuR8wDgYDVR0PAQH/BAQDAgZAMBIGA1UdIAQLMAkwBwYFKyQIAQEwfwYD"
            + "VR0fBHgwdjB0oCygKoYobGRhcDovL2Rpci5zaWdudHJ1c3QuZGUvbz1TaWdu"
            + "dHJ1c3QsYz1kZaJEpEIwQDEdMBsGA1UEAxMUQ1JMU2lnblNpZ250cnVzdDE6"
            + "UE4xEjAQBgNVBAoTCVNpZ250cnVzdDELMAkGA1UEBhMCREUwYgYIKwYBBQUH"
            + "AQEEVjBUMFIGCCsGAQUFBzABhkZodHRwOi8vZGlyLnNpZ250cnVzdC5kZS9T"
            + "aWdudHJ1c3QvT0NTUC9zZXJ2bGV0L2h0dHBHYXRld2F5LlBvc3RIYW5kbGVy"
            + "MBgGCCsGAQUFBwEDBAwwCjAIBgYEAI5GAQEwDgYHAoIGAQoMAAQDAQH/MA0G"
            + "CSqGSIb3DQEBBQUAA4GBAHn1m3GcoyD5GBkKUY/OdtD6Sj38LYqYCF+qDbJR"
            + "6pqUBjY2wsvXepUppEler+stH8mwpDDSJXrJyuzf7xroDs4dkLl+Rs2x+2tg"
            + "BjU+ABkBDMsym2WpwgA8LCdymmXmjdv9tULxY+ec2pjSEzql6nEZNEfrU8nt"
            + "ZCSCavgqW4TtMYIBejCCAXYCAQEwUTBLMQswCQYDVQQGEwJERTESMBAGA1UE"
            + "ChQJU2lnbnRydXN0MSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEUNBIFNJR05U"
            + "UlVTVCAxOlBOAgJsxzAJBgUrDgMCGgUAoIGAMBgGCSqGSIb3DQEJAzELBgkq"
            + "hkiG9w0BBwEwIwYJKoZIhvcNAQkEMRYEFIYfhPoyfGzkLWWSSLjaHb4HQmaK"
            + "MBwGCSqGSIb3DQEJBTEPFw0wNTAzMjQwNzM4MzVaMCEGBSskCAYFMRgWFi92"
            + "YXIvZmlsZXMvdG1wXzEvdGVzdDEwDQYJKoZIhvcNAQEFBQAEgYA2IvA8lhVz"
            + "VD5e/itUxbFboKxeKnqJ5n/KuO/uBCl1N14+7Z2vtw1sfkIG+bJdp3OY2Cmn"
            + "mrQcwsN99Vjal4cXVj8t+DJzFG9tK9dSLvD3q9zT/GQ0kJXfimLVwCa4NaSf"
            + "Qsu4xtG0Rav6bCcnzabAkKuNNvKtH8amSRzk870DBg==");

        private static readonly byte[] xtraCounterSig = Base64.Decode(
              "MIIR/AYJKoZIhvcNAQcCoIIR7TCCEekCAQExCzAJBgUrDgMCGgUAMBoGCSqG"
            + "SIb3DQEHAaANBAtIZWxsbyB3b3JsZKCCDnkwggTPMIIDt6ADAgECAgRDnYD3"
            + "MA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNVBAYTAklUMRowGAYDVQQKExFJbi5U"
            + "ZS5TLkEuIFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5BLiAtIENlcnRpZmlj"
            + "YXRpb24gQXV0aG9yaXR5MB4XDTA4MDkxMjExNDMxMloXDTEwMDkxMjExNDMx"
            + "MlowgdgxCzAJBgNVBAYTAklUMSIwIAYDVQQKDBlJbnRlc2EgUy5wLkEuLzA1"
            + "MjYyODkwMDE0MSowKAYDVQQLDCFCdXNpbmVzcyBDb2xsYWJvcmF0aW9uICYg"
            + "U2VjdXJpdHkxHjAcBgNVBAMMFU1BU1NJTUlMSUFOTyBaSUNDQVJESTERMA8G"
            + "A1UEBAwIWklDQ0FSREkxFTATBgNVBCoMDE1BU1NJTUlMSUFOTzEcMBoGA1UE"
            + "BRMTSVQ6WkNDTVNNNzZIMTRMMjE5WTERMA8GA1UELhMIMDAwMDI1ODUwgaAw"
            + "DQYJKoZIhvcNAQEBBQADgY4AMIGKAoGBALeJTjmyFgx1SIP6c2AuB/kuyHo5"
            + "j/prKELTALsFDimre/Hxr3wOSet1TdQfFzU8Lu+EJqgfV9cV+cI1yeH1rZs7"
            + "lei7L3tX/VR565IywnguX5xwvteASgWZr537Fkws50bvTEMyYOj1Tf3FZvZU"
            + "z4n4OD39KI4mfR9i1eEVIxR3AgQAizpNo4IBoTCCAZ0wHQYDVR0RBBYwFIES"
            + "emljY2FyZGlAaW50ZXNhLml0MC8GCCsGAQUFBwEDBCMwITAIBgYEAI5GAQEw"
            + "CwYGBACORgEDAgEUMAgGBgQAjkYBBDBZBgNVHSAEUjBQME4GBgQAizABATBE"
            + "MEIGCCsGAQUFBwIBFjZodHRwOi8vZS10cnVzdGNvbS5pbnRlc2EuaXQvY2Ff"
            + "cHViYmxpY2EvQ1BTX0lOVEVTQS5odG0wDgYDVR0PAQH/BAQDAgZAMIGDBgNV"
            + "HSMEfDB6gBQZCQOW0bjFWBt+EORuxPagEgkQqKFcpFowWDELMAkGA1UEBhMC"
            + "SVQxGjAYBgNVBAoTEUluLlRlLlMuQS4gUy5wLkEuMS0wKwYDVQQDEyRJbi5U"
            + "ZS5TLkEuIC0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHmCBDzRARMwOwYDVR0f"
            + "BDQwMjAwoC6gLIYqaHR0cDovL2UtdHJ1c3Rjb20uaW50ZXNhLml0L0NSTC9J"
            + "TlRFU0EuY3JsMB0GA1UdDgQWBBTf5ItL8KmQh541Dxt7YxcWI1254TANBgkq"
            + "hkiG9w0BAQUFAAOCAQEAgW+uL1CVWQepbC/wfCmR6PN37Sueb4xiKQj2mTD5"
            + "UZ5KQjpivy/Hbuf0NrfKNiDEhAvoHSPC31ebGiKuTMFNyZPHfPEUnyYGSxea"
            + "2w837aXJFr6utPNQGBRi89kH90sZDlXtOSrZI+AzJJn5QK3F9gjcayU2NZXQ"
            + "MJgRwYmFyn2w4jtox+CwXPQ9E5XgxiMZ4WDL03cWVXDLX00EOJwnDDMUNTRI"
            + "m9Zv+4SKTNlfFbi9UTBqWBySkDzAelsfB2U61oqc2h1xKmCtkGMmN9iZT+Qz"
            + "ZC/vaaT+hLEBFGAH2gwFrYc4/jTBKyBYeU1vsAxsibIoTs1Apgl6MH75qPDL"
            + "BzCCBM8wggO3oAMCAQICBEOdgPcwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE"
            + "BhMCSVQxGjAYBgNVBAoTEUluLlRlLlMuQS4gUy5wLkEuMS0wKwYDVQQDEyRJ"
            + "bi5UZS5TLkEuIC0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwOTEy"
            + "MTE0MzEyWhcNMTAwOTEyMTE0MzEyWjCB2DELMAkGA1UEBhMCSVQxIjAgBgNV"
            + "BAoMGUludGVzYSBTLnAuQS4vMDUyNjI4OTAwMTQxKjAoBgNVBAsMIUJ1c2lu"
            + "ZXNzIENvbGxhYm9yYXRpb24gJiBTZWN1cml0eTEeMBwGA1UEAwwVTUFTU0lN"
            + "SUxJQU5PIFpJQ0NBUkRJMREwDwYDVQQEDAhaSUNDQVJESTEVMBMGA1UEKgwM"
            + "TUFTU0lNSUxJQU5PMRwwGgYDVQQFExNJVDpaQ0NNU003NkgxNEwyMTlZMREw"
            + "DwYDVQQuEwgwMDAwMjU4NTCBoDANBgkqhkiG9w0BAQEFAAOBjgAwgYoCgYEA"
            + "t4lOObIWDHVIg/pzYC4H+S7IejmP+msoQtMAuwUOKat78fGvfA5J63VN1B8X"
            + "NTwu74QmqB9X1xX5wjXJ4fWtmzuV6Lsve1f9VHnrkjLCeC5fnHC+14BKBZmv"
            + "nfsWTCznRu9MQzJg6PVN/cVm9lTPifg4Pf0ojiZ9H2LV4RUjFHcCBACLOk2j"
            + "ggGhMIIBnTAdBgNVHREEFjAUgRJ6aWNjYXJkaUBpbnRlc2EuaXQwLwYIKwYB"
            + "BQUHAQMEIzAhMAgGBgQAjkYBATALBgYEAI5GAQMCARQwCAYGBACORgEEMFkG"
            + "A1UdIARSMFAwTgYGBACLMAEBMEQwQgYIKwYBBQUHAgEWNmh0dHA6Ly9lLXRy"
            + "dXN0Y29tLmludGVzYS5pdC9jYV9wdWJibGljYS9DUFNfSU5URVNBLmh0bTAO"
            + "BgNVHQ8BAf8EBAMCBkAwgYMGA1UdIwR8MHqAFBkJA5bRuMVYG34Q5G7E9qAS"
            + "CRCooVykWjBYMQswCQYDVQQGEwJJVDEaMBgGA1UEChMRSW4uVGUuUy5BLiBT"
            + "LnAuQS4xLTArBgNVBAMTJEluLlRlLlMuQS4gLSBDZXJ0aWZpY2F0aW9uIEF1"
            + "dGhvcml0eYIEPNEBEzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vZS10cnVz"
            + "dGNvbS5pbnRlc2EuaXQvQ1JML0lOVEVTQS5jcmwwHQYDVR0OBBYEFN/ki0vw"
            + "qZCHnjUPG3tjFxYjXbnhMA0GCSqGSIb3DQEBBQUAA4IBAQCBb64vUJVZB6ls"
            + "L/B8KZHo83ftK55vjGIpCPaZMPlRnkpCOmK/L8du5/Q2t8o2IMSEC+gdI8Lf"
            + "V5saIq5MwU3Jk8d88RSfJgZLF5rbDzftpckWvq6081AYFGLz2Qf3SxkOVe05"
            + "Ktkj4DMkmflArcX2CNxrJTY1ldAwmBHBiYXKfbDiO2jH4LBc9D0TleDGIxnh"
            + "YMvTdxZVcMtfTQQ4nCcMMxQ1NEib1m/7hIpM2V8VuL1RMGpYHJKQPMB6Wx8H"
            + "ZTrWipzaHXEqYK2QYyY32JlP5DNkL+9ppP6EsQEUYAfaDAWthzj+NMErIFh5"
            + "TW+wDGyJsihOzUCmCXowfvmo8MsHMIIEzzCCA7egAwIBAgIEQ52A9zANBgkq"
            + "hkiG9w0BAQUFADBYMQswCQYDVQQGEwJJVDEaMBgGA1UEChMRSW4uVGUuUy5B"
            + "LiBTLnAuQS4xLTArBgNVBAMTJEluLlRlLlMuQS4gLSBDZXJ0aWZpY2F0aW9u"
            + "IEF1dGhvcml0eTAeFw0wODA5MTIxMTQzMTJaFw0xMDA5MTIxMTQzMTJaMIHY"
            + "MQswCQYDVQQGEwJJVDEiMCAGA1UECgwZSW50ZXNhIFMucC5BLi8wNTI2Mjg5"
            + "MDAxNDEqMCgGA1UECwwhQnVzaW5lc3MgQ29sbGFib3JhdGlvbiAmIFNlY3Vy"
            + "aXR5MR4wHAYDVQQDDBVNQVNTSU1JTElBTk8gWklDQ0FSREkxETAPBgNVBAQM"
            + "CFpJQ0NBUkRJMRUwEwYDVQQqDAxNQVNTSU1JTElBTk8xHDAaBgNVBAUTE0lU"
            + "OlpDQ01TTTc2SDE0TDIxOVkxETAPBgNVBC4TCDAwMDAyNTg1MIGgMA0GCSqG"
            + "SIb3DQEBAQUAA4GOADCBigKBgQC3iU45shYMdUiD+nNgLgf5Lsh6OY/6ayhC"
            + "0wC7BQ4pq3vx8a98DknrdU3UHxc1PC7vhCaoH1fXFfnCNcnh9a2bO5Xouy97"
            + "V/1UeeuSMsJ4Ll+ccL7XgEoFma+d+xZMLOdG70xDMmDo9U39xWb2VM+J+Dg9"
            + "/SiOJn0fYtXhFSMUdwIEAIs6TaOCAaEwggGdMB0GA1UdEQQWMBSBEnppY2Nh"
            + "cmRpQGludGVzYS5pdDAvBggrBgEFBQcBAwQjMCEwCAYGBACORgEBMAsGBgQA"
            + "jkYBAwIBFDAIBgYEAI5GAQQwWQYDVR0gBFIwUDBOBgYEAIswAQEwRDBCBggr"
            + "BgEFBQcCARY2aHR0cDovL2UtdHJ1c3Rjb20uaW50ZXNhLml0L2NhX3B1YmJs"
            + "aWNhL0NQU19JTlRFU0EuaHRtMA4GA1UdDwEB/wQEAwIGQDCBgwYDVR0jBHww"
            + "eoAUGQkDltG4xVgbfhDkbsT2oBIJEKihXKRaMFgxCzAJBgNVBAYTAklUMRow"
            + "GAYDVQQKExFJbi5UZS5TLkEuIFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5B"
            + "LiAtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5ggQ80QETMDsGA1UdHwQ0MDIw"
            + "MKAuoCyGKmh0dHA6Ly9lLXRydXN0Y29tLmludGVzYS5pdC9DUkwvSU5URVNB"
            + "LmNybDAdBgNVHQ4EFgQU3+SLS/CpkIeeNQ8be2MXFiNdueEwDQYJKoZIhvcN"
            + "AQEFBQADggEBAIFvri9QlVkHqWwv8Hwpkejzd+0rnm+MYikI9pkw+VGeSkI6"
            + "Yr8vx27n9Da3yjYgxIQL6B0jwt9XmxoirkzBTcmTx3zxFJ8mBksXmtsPN+2l"
            + "yRa+rrTzUBgUYvPZB/dLGQ5V7Tkq2SPgMySZ+UCtxfYI3GslNjWV0DCYEcGJ"
            + "hcp9sOI7aMfgsFz0PROV4MYjGeFgy9N3FlVwy19NBDicJwwzFDU0SJvWb/uE"
            + "ikzZXxW4vVEwalgckpA8wHpbHwdlOtaKnNodcSpgrZBjJjfYmU/kM2Qv72mk"
            + "/oSxARRgB9oMBa2HOP40wSsgWHlNb7AMbImyKE7NQKYJejB++ajwywcxggM8"
            + "MIIDOAIBATBgMFgxCzAJBgNVBAYTAklUMRowGAYDVQQKExFJbi5UZS5TLkEu"
            + "IFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5BLiAtIENlcnRpZmljYXRpb24g"
            + "QXV0aG9yaXR5AgRDnYD3MAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEgYB+"
            + "lH2cwLqc91mP8prvgSV+RRzk13dJdZvdoVjgQoFrPhBiZCNIEoHvIhMMA/sM"
            + "X6euSRZk7EjD24FasCEGYyd0mJVLEy6TSPmuW+wWz/28w3a6IWXBGrbb/ild"
            + "/CJMkPgLPGgOVD1WDwiNKwfasiQSFtySf5DPn3jFevdLeMmEY6GCAjIwggEV"
            + "BgkqhkiG9w0BCQYxggEGMIIBAgIBATBgMFgxCzAJBgNVBAYTAklUMRowGAYD"
            + "VQQKExFJbi5UZS5TLkEuIFMucC5BLjEtMCsGA1UEAxMkSW4uVGUuUy5BLiAt"
            + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5AgRDnYD3MAkGBSsOAwIaBQAwDQYJ"
            + "KoZIhvcNAQEBBQAEgYBHlOULfT5GDigIvxP0qZOy8VbpntmzaPF55VV4buKV"
            + "35J+uHp98gXKp0LrHM69V5IRKuyuQzHHFBqsXxsRI9o6KoOfgliD9Xc+BeMg"
            + "dKzQhBhBYoFREq8hQM0nSbqDNHYAQyNHMzUA/ZQUO5dlFuH8Dw3iDYAhNtfd"
            + "PrlchKJthDCCARUGCSqGSIb3DQEJBjGCAQYwggECAgEBMGAwWDELMAkGA1UE"
            + "BhMCSVQxGjAYBgNVBAoTEUluLlRlLlMuQS4gUy5wLkEuMS0wKwYDVQQDEyRJ"
            + "bi5UZS5TLkEuIC0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkCBEOdgPcwCQYF"
            + "Kw4DAhoFADANBgkqhkiG9w0BAQEFAASBgEeU5Qt9PkYOKAi/E/Spk7LxVume"
            + "2bNo8XnlVXhu4pXfkn64en3yBcqnQusczr1XkhEq7K5DMccUGqxfGxEj2joq"
            + "g5+CWIP1dz4F4yB0rNCEGEFigVESryFAzSdJuoM0dgBDI0czNQD9lBQ7l2UW"
            + "4fwPDeINgCE2190+uVyEom2E");

        private static readonly byte[] signedData_mldsa44 = LoadPemContents("pkix/cms/mldsa", "SignedData_ML-DSA-44.pem");
        private static readonly byte[] signedData_mldsa65 = LoadPemContents("pkix/cms/mldsa", "SignedData_ML-DSA-65.pem");
        private static readonly byte[] signedData_mldsa87 = LoadPemContents("pkix/cms/mldsa", "SignedData_ML-DSA-87.pem");

        private static byte[] LoadPemContents(string path, string name)
        {
            using (var pemReader = new PemReader(new StreamReader(SimpleTest.FindTestResource(path, name))))
            {
                return pemReader.ReadPemObject().Content;
            }
        }

        static SignedDataTest()
        {
            // TODO Move functionality of NoParams to SignerUtilities?

            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            NoParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
            NoParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha224);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha256);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha384);
            NoParams.Add(NistObjectIdentifiers.DsaWithSha512);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_224);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_256);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_384);
            NoParams.Add(NistObjectIdentifiers.IdDsaWithSha3_512);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_224);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_256);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_384);
            NoParams.Add(NistObjectIdentifiers.IdEcdsaWithSha3_512);
            NoParams.Add(EdECObjectIdentifiers.id_Ed25519);
            NoParams.Add(EdECObjectIdentifiers.id_Ed448);
            NoParams.Add(NistObjectIdentifiers.id_ml_dsa_44);
            NoParams.Add(NistObjectIdentifiers.id_ml_dsa_65);
            NoParams.Add(NistObjectIdentifiers.id_ml_dsa_87);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_sha2_128f);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_sha2_128s);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_sha2_192f);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_sha2_192s);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_sha2_256f);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_sha2_256s);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_shake_128f);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_shake_128s);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_shake_192f);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_shake_192s);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_shake_256f);
            NoParams.Add(NistObjectIdentifiers.id_slh_dsa_shake_256s);
        }

        [Test]
        public void TestDetachedVerification()
        {
            byte[] data = Encoding.ASCII.GetBytes("Hello World!");
            CmsProcessable msg = new CmsProcessableByteArray(data);

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestMD5);
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(msg);

            var hashes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                { CmsSignedGenerator.DigestSha1, DigestUtilities.CalculateDigest("SHA1", data) },
                { CmsSignedGenerator.DigestMD5, DigestUtilities.CalculateDigest("MD5", data) },
            };

            s = new CmsSignedData(hashes, s.GetEncoded());

            VerifySignatures(s);
        }

        [Test]
        public void TestSha1AndMD5WithRsaEncapsulatedRepeated()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestMD5);
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();

            SignerInformationStore signers = s.GetSignerInfos();

            Assert.AreEqual(2, signers.Count);

            SignerID sid = null;
            var c = signers.GetSigners();

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                sid = signer.SignerID;

                Assert.True(signer.Verify(cert));

                //
                // check content digest
                //

                Assert.True(gen.GetGeneratedDigests().TryGetValue(signer.DigestAlgorithmID.Algorithm.GetID(),
                    out var contentDigest));

                Asn1.Cms.AttributeTable table = signer.SignedAttributes;
                Asn1.Cms.Attribute hash = table[CmsAttributes.MessageDigest];

                Assert.True(Arrays.AreEqual(contentDigest, ((Asn1OctetString)hash.AttrValues[0]).GetOctets()));
            }

            c = signers.GetSigners(sid);

            Assert.AreEqual(2, c.Count);

            //
            // try using existing signer
            //

            gen = new CmsSignedDataGenerator();

            gen.AddSigners(s.GetSignerInfos());

            gen.AddCertificates(s.GetCertificates());
            gen.AddCrls(s.GetCrls());

            s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();

            signers = s.GetSignerInfos();
            c = signers.GetSigners();

            Assert.AreEqual(2, c.Count);

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            CheckSignerStoreReplacement(s, signers);
        }

        [Test]
        public void TestSha1AndMD5WithRsaEncapsulatedRepeatedWithSignerInfoGen()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory("SHA1withRSA", OrigKP.Private), OrigCert));
            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory("MD5withRSA", OrigKP.Private), OrigCert));

            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();

            SignerInformationStore signers = s.GetSignerInfos();

            Assert.AreEqual(2, signers.Count);

            SignerID sid = null;
            var c = signers.GetSigners();

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                sid = signer.SignerID;

                Assert.True(signer.Verify(cert));

                //
                // check content digest
                //

                Assert.True(gen.GetGeneratedDigests().TryGetValue(signer.DigestAlgorithmID.Algorithm.GetID(),
                    out var contentDigest));

                Asn1.Cms.AttributeTable table = signer.SignedAttributes;
                Asn1.Cms.Attribute hash = table[CmsAttributes.MessageDigest];

                Assert.True(Arrays.AreEqual(contentDigest, ((Asn1OctetString)hash.AttrValues[0]).GetOctets()));
            }

            c = signers.GetSigners(sid);

            Assert.AreEqual(2, c.Count);

            //
            // try using existing signer
            //

            gen = new CmsSignedDataGenerator();

            gen.AddSigners(s.GetSignerInfos());

            gen.AddCertificates(s.GetCertificates());
            gen.AddCrls(s.GetCrls());

            s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();

            signers = s.GetSignerInfos();
            c = signers.GetSigners();

            Assert.AreEqual(2, c.Count);

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            CheckSignerStoreReplacement(s, signers);
        }

        [Test]
        public void TestWithDefiniteLength()
        {
            byte[] msgBytes = Encoding.ASCII.GetBytes("Hello World!");
            CmsProcessable msg = new CmsProcessableByteArray(msgBytes);

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();

            var signatureFactory = new Asn1SignatureFactory("SHA1withRSA", OrigKP.Private);
            var signerInfoGenerator = new SignerInfoGeneratorBuilder()
                .SetDirectSignature(true)
                .Build(signatureFactory, OrigCert);

            gen.AddSignerInfoGenerator(signerInfoGenerator);

            gen.AddCertificates(x509Certs);

            gen.UseDefiniteLength = true;

            CmsSignedData s = gen.Generate(msg, false);

            Assert.True(s.ContentInfo.ToAsn1Object().GetType() == typeof(DLSequence));

            Asn1Encodable content = s.ContentInfo.Content;
            Assert.True(content is SignedData);
            Assert.True(content.ToAsn1Object().GetType() == typeof(DLSequence));

            byte[] expectedContentDigest = DigestUtilities.CalculateDigest("SHA1", msgBytes);

            VerifySignatures(s, expectedContentDigest);
        }

        // NB: C# build doesn't support "no attributes" version of CmsSignedDataGenerator.Generate
        //[Test]
        //public void TestSha1WithRsaNoAttributes()
        //{
        //    CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello world!"));

        //    IX509Store x509Certs = MakeCertStore(OrigCert, SignCert);

        //    CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
        //    gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
        //    gen.AddCertificates(x509Certs);

        //    CmsSignedData s = gen.Generate(CmsSignedGenerator.Data, msg, false, false);

        //    byte[] testBytes = Encoding.ASCII.GetBytes("Hello world!");

        //    // compute expected content digest
        //    byte[] hash = DigestUtilities.CalculateDigest("SHA1", testBytes);

        //    VerifySignatures(s, hash);
        //}

        [Test]
        public void TestSha1WithRsaAndAttributeTable()
        {
            byte[] testBytes = Encoding.ASCII.GetBytes("Hello world!");
            CmsProcessable msg = new CmsProcessableByteArray(testBytes);

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            byte[] hash = DigestUtilities.CalculateDigest("SHA1", testBytes);

            Asn1.Cms.Attribute attr = new Asn1.Cms.Attribute(CmsAttributes.MessageDigest,
                new DerSet(new DerOctetString(hash)));

            Asn1EncodableVector v = new Asn1EncodableVector(attr);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(SignKP.Private, SignCert, CmsSignedGenerator.DigestSha1,
                new Asn1.Cms.AttributeTable(v), null);
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(CmsSignedGenerator.Data, null, false);

            //
            // the signature is detached, so need to add msg before passing on
            //
            s = new CmsSignedData(msg, s.GetEncoded());

            //
            // compute expected content digest
            //
            VerifySignatures(s, hash);
        }

        [Test]
        public void TestRawSha256MissingNull()
        {
            byte[] document = GetInput("rawsha256nonull.p7m");

            CmsSignedData s = new CmsSignedData(document);

            var certStore = s.GetCertificates();
            foreach (SignerInformation signerInformation in s.GetSignerInfos().GetSigners())
            {
                var certCollection = certStore.EnumerateMatches(signerInformation.SignerID);
                foreach (X509Certificate cert in certCollection)
                {
                    Assert.True(signerInformation.Verify(cert), "raw sig failed");
                }
            }
        }

        [Test]
        public void TestSha1WithRsaEncapsulated()
        {
            EncapsulatedTest(SignKP, SignCert, CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestSha1WithRsaEncapsulatedSubjectKeyID()
        {
            SubjectKeyIDTest(SignKP, SignCert, CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestSha1WithRsaPss()
        {
            RsaPssTest("SHA1", CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestSha224WithRsaPss()
        {
            RsaPssTest("SHA224", CmsSignedGenerator.DigestSha224);
        }

        [Test]
        public void TestSha256WithRsaPss()
        {
            RsaPssTest("SHA256", CmsSignedGenerator.DigestSha256);
        }

        [Test]
        public void TestSha256WithRsaPssDirect()
        {
            RsaPssDirectTest("SHA256");
        }

        [Test]
        public void TestSha384WithRsaPss()
        {
            RsaPssTest("SHA384", CmsSignedGenerator.DigestSha384);
        }

        [Test]
        public void TestSha1WithRsaDigest()
        {
            RsaDigestTest("SHA1withRSA");
        }

        [Test]
        public void TestSha224WithRsaDigest()
        {
            RsaDigestTest("SHA224withRSA");
        }

        [Test]
        public void TestSha256WithRsaDigest()
        {
            RsaDigestTest("SHA256withRSA");
        }

        [Test]
        public void TestSha384WithRsaDigest()
        {
            RsaDigestTest("SHA384withRSA");
        }

        [Test]
        public void TestSha512WithRsaDigest()
        {
            RsaDigestTest("SHA512withRSA");
        }

        [Test]
        public void TestSha3_224WithRsaDigest()
        {
            RsaDigestTest("SHA3-224withRSA");
        }

        [Test]
        public void TestSha3_256WithRsaDigest()
        {
            RsaDigestTest("SHA3-256withRSA");
        }

        [Test]
        public void TestSha3_384WithRsaDigest()
        {
            RsaDigestTest("SHA3-384withRSA");
        }

        [Test]
        public void TestSha3_512WithRsaDigest()
        {
            RsaDigestTest("SHA3-512withRSA");
        }

        [Test]
        public void TestSHA512_224ithRSADigest()
        {
            RsaDigestTest("SHA512(224)withRSA");
        }

        [Test]
        public void TestSHA512_256ithRSADigest()
        {
            RsaDigestTest("SHA512(256)withRSA");
        }

        [Test]
        public void TestEd25519()
        {
            /*
             * RFC 8419 3.1. When signing with Ed25519, the digestAlgorithm MUST be id-sha512, and the algorithm
             * parameters field MUST be absent.
             * 
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignEd25519KP, SignEd25519Cert, "Ed25519", EdECObjectIdentifiers.id_Ed25519, expectedDigAlgID);

            EncapsulatedTestAlt(SignEd25519KP, SignEd25519Cert, "Ed25519", EdECObjectIdentifiers.id_Ed25519,
                expectedDigAlgID);
        }

        //[Test]
        //public void TestEd448()
        //{
        //    /*
        //     * RFC 8419 3.1. When signing with Ed448, the digestAlgorithm MUST be id-shake256-len, the algorithm
        //     * parameters field MUST be present, and the parameter MUST contain 512, encoded as a positive integer
        //     * value.
        //     * 
        //     * We confirm here that our implementation defaults to id-shake256-len/512 for the digest algorithm.
        //     */
        //    AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256Len,
        //        new DerInteger(512));

        //    DetachedTest(SignEd448KP, SignEd448Cert, "Ed448", EdECObjectIdentifiers.id_Ed448, expectedDigAlgID);

        //    EncapsulatedTestAlt(SignEd448KP, SignEd448Cert, "Ed448", EdECObjectIdentifiers.id_Ed448, expectedDigAlgID);
        //}

        [Test]
        public void TestSha224WithRsaEncapsulated()
        {
            EncapsulatedTest(SignKP, SignCert, CmsSignedGenerator.DigestSha224);
        }

        [Test]
        public void TestSha256WithRsaEncapsulated()
        {
            EncapsulatedTest(SignKP, SignCert, CmsSignedGenerator.DigestSha256);
        }

        [Test]
        public void TestRipeMD128WithRsaEncapsulated()
        {
            EncapsulatedTest(SignKP, SignCert, CmsSignedGenerator.DigestRipeMD128);
        }

        [Test]
        public void TestRipeMD160WithRsaEncapsulated()
        {
            EncapsulatedTest(SignKP, SignCert, CmsSignedGenerator.DigestRipeMD160);
        }

        [Test]
        public void TestRipeMD256WithRsaEncapsulated()
        {
            EncapsulatedTest(SignKP, SignCert, CmsSignedGenerator.DigestRipeMD256);
        }

        [Test]
        public void TestSha224WithDsaEncapsulated()
        {
            EncapsulatedTest(SignDsaKP, SignDsaCert, CmsSignedGenerator.DigestSha224);
        }

        [Test]
        public void TestSha256WithDsaEncapsulated()
        {
            EncapsulatedTest(SignDsaKP, SignDsaCert, CmsSignedGenerator.DigestSha256);
        }

        [Test]
        public void TestSha384WithDsaEncapsulated()
        {
            EncapsulatedTest(SignDsaKP, SignDsaCert, CmsSignedGenerator.DigestSha384);
        }

        [Test]
        public void TestSha512WithDsaEncapsulated()
        {
            EncapsulatedTest(SignDsaKP, SignDsaCert, CmsSignedGenerator.DigestSha512);
        }

        [Test]
        public void TestECDsaEncapsulated()
        {
            EncapsulatedTest(SignECDsaKP, SignECDsaCert, CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestECDsaEncapsulatedSubjectKeyID()
        {
            SubjectKeyIDTest(SignECDsaKP, SignECDsaCert, CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestECDsaSha224Encapsulated()
        {
            EncapsulatedTest(SignECDsaKP, SignECDsaCert, CmsSignedGenerator.DigestSha224);
        }

        [Test]
        public void TestECDsaSha256Encapsulated()
        {
            EncapsulatedTest(SignECDsaKP, SignECDsaCert, CmsSignedGenerator.DigestSha256);
        }

        [Test]
        public void TestECDsaSha384Encapsulated()
        {
            EncapsulatedTest(SignECDsaKP, SignECDsaCert, CmsSignedGenerator.DigestSha384);
        }

        [Test]
        public void TestECDsaSha512Encapsulated()
        {
            EncapsulatedTest(SignECDsaKP, SignECDsaCert, CmsSignedGenerator.DigestSha512);
        }

        [Test]
        public void TestECDsaSha512EncapsulatedWithKeyFactoryAsEC()
        {
            byte[] pubEnc = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(SignECDsaKP.Public).GetDerEncoded();
            byte[] privEnc = PrivateKeyInfoFactory.CreatePrivateKeyInfo(SignECDsaKP.Private).GetDerEncoded();
            AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(
                PublicKeyFactory.CreateKey(pubEnc),
                PrivateKeyFactory.CreateKey(privEnc));

            EncapsulatedTest(kp, SignECDsaCert, CmsSignedGenerator.DigestSha512);
        }

        [Test]
        public void TestECDsaSha3_224Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-224withECDSA");
        }

        [Test]
        public void TestECDsaSha3_256Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-256withECDSA");
        }

        [Test]
        public void TestECDsaSha3_384Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-384withECDSA");
        }

        [Test]
        public void TestECDsaSha3_512Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-512withECDSA");
        }

        [Test]
        public void TestPlainECDsaSha224Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA224withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha256Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA256withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha384Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA384withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha512Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA512withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha3_224Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-224withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha3_256Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-256withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha3_384Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-384withPLAIN-ECDSA");
        }

        [Test]
        public void TestPlainECDsaSha3_512Encapsulated()
        {
            EncapsulatedTestAlt(SignECDsaKP, SignECDsaCert, "SHA3-512withPLAIN-ECDSA");
        }

        [Test]
        public void TestDsaEncapsulated()
        {
            EncapsulatedTest(SignDsaKP, SignDsaCert, CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestDsaEncapsulatedSubjectKeyID()
        {
            SubjectKeyIDTest(SignDsaKP, SignDsaCert, CmsSignedGenerator.DigestSha1);
        }

        [Test]
        public void TestGost3411WithGost3410Encapsulated()
        {
            EncapsulatedTest(SignGostKP, SignGostCert, CmsSignedGenerator.DigestGost3411);
        }

        [Test]
        public void TestGost3411WithECGost3410Encapsulated()
        {
            EncapsulatedTest(SignECGostKP, SignECGostCert, CmsSignedGenerator.DigestGost3411);
        }

        [Test]
        public void TestSha1WithRsaCounterSignature()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(SignCert, OrigCert);
            var x509Crls = CmsTestUtil.MakeCrlStore(SignCrl);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(SignKP.Private, SignCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);
            gen.AddCrls(x509Crls);

            CmsSignedData s = gen.Generate(msg, true);
            SignerInformation origSigner = s.GetSignerInfos().GetSigners()[0];
            SignerInformationStore counterSigners1 = gen.GenerateCounterSigners(origSigner);
            SignerInformationStore counterSigners2 = gen.GenerateCounterSigners(origSigner);

            SignerInformation signer1 = SignerInformation.AddCounterSigners(origSigner, counterSigners1);
            SignerInformation signer2 = SignerInformation.AddCounterSigners(signer1, counterSigners2);

            SignerInformationStore cs = signer2.GetCounterSignatures();
            var csSigners = cs.GetSigners();
            Assert.AreEqual(2, csSigners.Count);

            foreach (SignerInformation cSigner in csSigners)
            {
                var certCollection = x509Certs.EnumerateMatches(cSigner.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.Null(cSigner.SignedAttributes[Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtContentType]);
                Assert.True(cSigner.Verify(cert));
            }
        }

        [Test]
        public void TestAddDigestAlgorithm()
        {
            var ripeMD160 = new AlgorithmIdentifier(TeleTrusTObjectIdentifiers.RipeMD160, DerNull.Instance);
            var sha1Null = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            var sha1Omit = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);

            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(SignCert, OrigCert);
            var x509Crls = CmsTestUtil.MakeCrlStore(SignCrl);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();

            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory("SHA1withRSA", SignKP.Private), SignCert));

            gen.AddCertificates(x509Certs);
            gen.AddCrls(x509Crls);

            CmsSignedData s = gen.Generate(msg, true);

            var digestAlgorithms = new HashSet<AlgorithmIdentifier>(s.GetDigestAlgorithms());
            Assert.AreEqual(1, digestAlgorithms.Count);
            Assert.True(digestAlgorithms.Contains(sha1Null));

            VerifySignatures(s);

            CmsSignedData oldS = s;

            s = CmsSignedData.AddDigestAlgorithm(s, sha1Null);
            Assert.AreSame(oldS, s);

            s = CmsSignedData.AddDigestAlgorithm(s, sha1Omit);
            Assert.AreSame(oldS, s);

            s = CmsSignedData.AddDigestAlgorithm(s, ripeMD160);
            Assert.AreNotSame(oldS, s);

            var newDigestAlgorithms = new HashSet<AlgorithmIdentifier>(s.GetDigestAlgorithms());
            Assert.AreEqual(2, newDigestAlgorithms.Count);
            Assert.True(newDigestAlgorithms.Contains(sha1Null));
            Assert.True(newDigestAlgorithms.Contains(ripeMD160));
        }

        [Test]
        public void TestMLDsa44()
        {
            /*
             * draft-ietf-lamps-cms-ml-dsa-03 3.3. SHA-512 [FIPS180] MUST be supported for use with the variants
             * of ML-DSA in this document; however, other hash functions MAY also be supported. When SHA-512 is
             * used, the id-sha512 [RFC5754] digest algorithm identifier is used and the parameters field MUST be
             * omitted.
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier sha512 = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignMLDsa44KP, SignMLDsa44Cert, "ML-DSA-44", NistObjectIdentifiers.id_ml_dsa_44,
                expectedDigAlgID: sha512);

            EncapsulatedTestAlt(SignMLDsa44KP, SignMLDsa44Cert, "ML-DSA-44", NistObjectIdentifiers.id_ml_dsa_44,
                expectedDigAlgID: sha512);

            /*
             * TODO[cms] When SHAKE256 is used, the id-shake256[..] digest algorithm identifier is used and produces 512
             * bits of output, and the parameters field MUST be omitted.
             */
            //AlgorithmIdentifier shake256 = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);
        }

        [Test]
        public void TestMLDsa65()
        {
            /*
             * draft-ietf-lamps-cms-ml-dsa-03 3.3. SHA-512 [FIPS180] MUST be supported for use with the variants
             * of ML-DSA in this document; however, other hash functions MAY also be supported. When SHA-512 is
             * used, the id-sha512 [RFC5754] digest algorithm identifier is used and the parameters field MUST be
             * omitted.
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier sha512 = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignMLDsa65KP, SignMLDsa65Cert, "ML-DSA-65", NistObjectIdentifiers.id_ml_dsa_65,
                expectedDigAlgID: sha512);

            EncapsulatedTestAlt(SignMLDsa65KP, SignMLDsa65Cert, "ML-DSA-65", NistObjectIdentifiers.id_ml_dsa_65,
                expectedDigAlgID: sha512);

            /*
             * TODO[cms] When SHAKE256 is used, the id-shake256[..] digest algorithm identifier is used and produces 512
             * bits of output, and the parameters field MUST be omitted.
             */
            //AlgorithmIdentifier shake256 = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);
        }

        [Test]
        public void TestMLDsa87()
        {
            /*
             * draft-ietf-lamps-cms-ml-dsa-03 3.3. SHA-512 [FIPS180] MUST be supported for use with the variants
             * of ML-DSA in this document; however, other hash functions MAY also be supported. When SHA-512 is
             * used, the id-sha512 [RFC5754] digest algorithm identifier is used and the parameters field MUST be
             * omitted.
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier sha512 = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignMLDsa87KP, SignMLDsa87Cert, "ML-DSA-87", NistObjectIdentifiers.id_ml_dsa_87,
                expectedDigAlgID: sha512);

            EncapsulatedTestAlt(SignMLDsa87KP, SignMLDsa87Cert, "ML-DSA-87", NistObjectIdentifiers.id_ml_dsa_87,
                expectedDigAlgID: sha512);

            /*
             * TODO[cms] When SHAKE256 is used, the id-shake256[..] digest algorithm identifier is used and produces 512
             * bits of output, and the parameters field MUST be omitted.
             */
            //AlgorithmIdentifier shake256 = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);
        }

        [Test]
        public void TestSlhDsa_Sha2_128f()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHA-256 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);

            DetachedTest(SignSlhDsa_Sha2_128f_KP, SignSlhDsa_Sha2_128f_Cert, "SLH-DSA-SHA2-128F",
                NistObjectIdentifiers.id_slh_dsa_sha2_128f, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Sha2_128f_KP, SignSlhDsa_Sha2_128f_Cert, "SLH-DSA-SHA2-128F",
                NistObjectIdentifiers.id_slh_dsa_sha2_128f, expectedDigAlgID);
        }

        [Test, Explicit]
        public void TestSlhDsa_Sha2_128s()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHA-256 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);

            DetachedTest(SignSlhDsa_Sha2_128s_KP, SignSlhDsa_Sha2_128s_Cert, "SLH-DSA-SHA2-128S",
                NistObjectIdentifiers.id_slh_dsa_sha2_128s, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Sha2_128s_KP, SignSlhDsa_Sha2_128s_Cert, "SLH-DSA-SHA2-128S",
                NistObjectIdentifiers.id_slh_dsa_sha2_128s, expectedDigAlgID);
        }

        [Test]
        public void TestSlhDsa_Sha2_192f()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignSlhDsa_Sha2_192f_KP, SignSlhDsa_Sha2_192f_Cert, "SLH-DSA-SHA2-192F",
                NistObjectIdentifiers.id_slh_dsa_sha2_192f, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Sha2_192f_KP, SignSlhDsa_Sha2_192f_Cert, "SLH-DSA-SHA2-192F",
                NistObjectIdentifiers.id_slh_dsa_sha2_192f, expectedDigAlgID);
        }

        [Test, Explicit]
        public void TestSlhDsa_Sha2_192s()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignSlhDsa_Sha2_192s_KP, SignSlhDsa_Sha2_192s_Cert, "SLH-DSA-SHA2-192S",
                NistObjectIdentifiers.id_slh_dsa_sha2_192s, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Sha2_192s_KP, SignSlhDsa_Sha2_192s_Cert, "SLH-DSA-SHA2-192S",
                NistObjectIdentifiers.id_slh_dsa_sha2_192s, expectedDigAlgID);
        }

        [Test]
        public void TestSlhDsa_Sha2_256f()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignSlhDsa_Sha2_256f_KP, SignSlhDsa_Sha2_256f_Cert, "SLH-DSA-SHA2-256F",
                NistObjectIdentifiers.id_slh_dsa_sha2_256f, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Sha2_256f_KP, SignSlhDsa_Sha2_256f_Cert, "SLH-DSA-SHA2-256F",
                NistObjectIdentifiers.id_slh_dsa_sha2_256f, expectedDigAlgID);
        }

        [Test, Explicit]
        public void TestSlhDsa_Sha2_256s()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHA-512 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);

            DetachedTest(SignSlhDsa_Sha2_256s_KP, SignSlhDsa_Sha2_256s_Cert, "SLH-DSA-SHA2-256S",
                NistObjectIdentifiers.id_slh_dsa_sha2_256s, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Sha2_256s_KP, SignSlhDsa_Sha2_256s_Cert, "SLH-DSA-SHA2-256S",
                NistObjectIdentifiers.id_slh_dsa_sha2_256s, expectedDigAlgID);
        }

        [Test]
        public void TestSlhDsa_Shake_128f()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHAKE-128 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake128);

            DetachedTest(SignSlhDsa_Shake_128f_KP, SignSlhDsa_Shake_128f_Cert, "SLH-DSA-SHAKE-128F",
                NistObjectIdentifiers.id_slh_dsa_shake_128f, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Shake_128f_KP, SignSlhDsa_Shake_128f_Cert, "SLH-DSA-SHAKE-128F",
                NistObjectIdentifiers.id_slh_dsa_shake_128f, expectedDigAlgID);
        }

        [Test, Explicit]
        public void TestSlhDsa_Shake_128s()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHAKE-128 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake128);

            DetachedTest(SignSlhDsa_Shake_128s_KP, SignSlhDsa_Shake_128s_Cert, "SLH-DSA-SHAKE-128S",
                NistObjectIdentifiers.id_slh_dsa_shake_128s, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Shake_128s_KP, SignSlhDsa_Shake_128s_Cert, "SLH-DSA-SHAKE-128S",
                NistObjectIdentifiers.id_slh_dsa_shake_128s, expectedDigAlgID);
        }

        [Test]
        public void TestSlhDsa_Shake_192f()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHAKE-256 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);

            DetachedTest(SignSlhDsa_Shake_192f_KP, SignSlhDsa_Shake_192f_Cert, "SLH-DSA-SHAKE-192F",
                NistObjectIdentifiers.id_slh_dsa_shake_192f, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Shake_192f_KP, SignSlhDsa_Shake_192f_Cert, "SLH-DSA-SHAKE-192F",
                NistObjectIdentifiers.id_slh_dsa_shake_192f, expectedDigAlgID);
        }

        [Test, Explicit]
        public void TestSlhDsa_Shake_192s()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHAKE-256 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);

            DetachedTest(SignSlhDsa_Shake_192s_KP, SignSlhDsa_Shake_192s_Cert, "SLH-DSA-SHAKE-192S",
                NistObjectIdentifiers.id_slh_dsa_shake_192s, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Shake_192s_KP, SignSlhDsa_Shake_192s_Cert, "SLH-DSA-SHAKE-192S",
                NistObjectIdentifiers.id_slh_dsa_shake_192s, expectedDigAlgID);
        }

        [Test]
        public void TestSlhDsa_Shake_256f()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHAKE-256 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);

            DetachedTest(SignSlhDsa_Shake_256f_KP, SignSlhDsa_Shake_256f_Cert, "SLH-DSA-SHAKE-256F",
                NistObjectIdentifiers.id_slh_dsa_shake_256f, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Shake_256f_KP, SignSlhDsa_Shake_256f_Cert, "SLH-DSA-SHAKE-256F",
                NistObjectIdentifiers.id_slh_dsa_shake_256f, expectedDigAlgID);
        }

        [Test, Explicit]
        public void TestSlhDsa_Shake_256s()
        {
            /*
             * draft-ietf-lamps-cms-sphincs-plus-19 4. (we initially only support the MUST-support algorithm)
             *
             * We confirm here that our implementation defaults to SHAKE-256 for the digest algorithm.
             */
            AlgorithmIdentifier expectedDigAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);

            DetachedTest(SignSlhDsa_Shake_256s_KP, SignSlhDsa_Shake_256s_Cert, "SLH-DSA-SHAKE-256S",
                NistObjectIdentifiers.id_slh_dsa_shake_256s, expectedDigAlgID);

            EncapsulatedTestAlt(SignSlhDsa_Shake_256s_KP, SignSlhDsa_Shake_256s_Cert, "SLH-DSA-SHAKE-256S",
                NistObjectIdentifiers.id_slh_dsa_shake_256s, expectedDigAlgID);
        }

        private static void RsaPssTest(string digestName, string digestOID)
        {
            byte[] msgBytes = Encoding.ASCII.GetBytes("Hello World!");
            CmsProcessable msg = new CmsProcessableByteArray(msgBytes);

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.EncryptionRsaPss, digestOID);
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(CmsSignedGenerator.Data, msg, false);

            // compute expected content digest
            byte[] expectedDigest = DigestUtilities.CalculateDigest(digestName, msgBytes);

            VerifySignatures(s, expectedDigest);
        }

        private static void RsaPssDirectTest(string digestName)
        {
            byte[] msgBytes = Encoding.ASCII.GetBytes("Hello World!");
            CmsProcessable msg = new CmsProcessableByteArray(msgBytes);

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().SetDirectSignature(true).Build(
                new Asn1SignatureFactory(digestName + "withRSAandMGF1", OrigKP.Private), OrigCert));
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(CmsSignedGenerator.Data, msg, false);

            // compute expected content digest
            byte[] expectedDigest = DigestUtilities.CalculateDigest(digestName, msgBytes);

            VerifyDirectSignatures(s, expectedDigest);
        }

        private static void SubjectKeyIDTest(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string digestAlgorithm)
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(signatureCert, OrigCert);
            var x509Crls = CmsTestUtil.MakeCrlStore(SignCrl);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(signaturePair.Private,
                CmsTestUtil.CreateSubjectKeyID(signatureCert.GetPublicKey()).GetKeyIdentifier(),
                digestAlgorithm);
            gen.AddCertificates(x509Certs);
            gen.AddCrls(x509Crls);

            CmsSignedData s = gen.Generate(msg, true);

            Assert.AreEqual(3, s.Version);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();
            x509Crls = s.GetCrls();

            SignerInformationStore signers = s.GetSignerInfos();

            foreach (SignerInformation signer in signers.GetSigners())
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            //
            // check for CRLs
            //
            var crls = new List<X509Crl>(x509Crls.EnumerateMatches(null));

            Assert.AreEqual(1, crls.Count);

            Assert.True(crls.Contains(SignCrl));

            //
            // try using existing signer
            //

            gen = new CmsSignedDataGenerator();

            gen.AddSigners(s.GetSignerInfos());

            gen.AddCertificates(s.GetCertificates());
            gen.AddCrls(s.GetCrls());

            s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();
            x509Crls = s.GetCrls();

            signers = s.GetSignerInfos();

            foreach (SignerInformation signer in signers.GetSigners())
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            CheckSignerStoreReplacement(s, signers);
        }

        private static void EncapsulatedTestAlt(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string signatureAlgorithm)
        {
            EncapsulatedTestAlt(signaturePair, signatureCert, signatureAlgorithm, sigAlgOid: null);
        }

        private static void EncapsulatedTestAlt(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string signatureAlgorithm, DerObjectIdentifier sigAlgOid)
        {
            EncapsulatedTestAlt(signaturePair, signatureCert, signatureAlgorithm, sigAlgOid, expectedDigAlgID: null);
        }

        private static void EncapsulatedTestAlt(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string signatureAlgorithm, DerObjectIdentifier sigAlgOid, AlgorithmIdentifier expectedDigAlgID)
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(signatureCert, OrigCert);
            var x509Crls = CmsTestUtil.MakeCrlStore(SignCrl);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();

            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory(signatureAlgorithm, signaturePair.Private), signatureCert));

            gen.AddCertificates(x509Certs);
            gen.AddCrls(x509Crls);

            CmsSignedData s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            var digestAlgorithms = new HashSet<AlgorithmIdentifier>(s.GetDigestAlgorithms());
            Assert.Greater(digestAlgorithms.Count, 0);

            if (expectedDigAlgID != null)
            {
                Assert.True(digestAlgorithms.Contains(expectedDigAlgID));
            }

            x509Certs = s.GetCertificates();
            x509Crls = s.GetCrls();

            SignerInformationStore signers = s.GetSignerInfos();

            foreach (SignerInformation signer in signers.GetSigners())
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                if (sigAlgOid != null)
                {
                    Assert.AreEqual(sigAlgOid, signer.SignatureAlgorithm.Algorithm);
                    if (NoParams.Contains(sigAlgOid))
                    {
                        Assert.Null(signer.SignatureAlgorithm.Parameters);
                    }
                    else
                    {
                        Assert.AreEqual(DerNull.Instance, signer.SignatureAlgorithm.Parameters);
                    }
                }

                digestAlgorithms.Remove(signer.DigestAlgorithmID);

                Assert.True(signer.Verify(cert));
            }

            Assert.AreEqual(0, digestAlgorithms.Count);

            //
            // check signer information lookup
            //

            // TODO[cms] Need equivalent constructor/helper
            //SignerId sid = new JcaSignerId(signatureCert);
            SignerID signerID;
            {
                var issuerAndSerialNumber = new Asn1.Cms.IssuerAndSerialNumber(signatureCert.CertificateStructure);

                signerID = new SignerID()
                {
                    Issuer = issuerAndSerialNumber.Issuer,
                    SerialNumber = issuerAndSerialNumber.SerialNumber.Value,
                };
            }

            var collection = signers.GetSigners(signerID);

            Assert.AreEqual(1, collection.Count);
            Assert.NotNull(collection[0]);

            //
            // check for CRLs
            //
            var crls = new List<X509Crl>(x509Crls.EnumerateMatches(null));

            Assert.AreEqual(1, crls.Count);

            Assert.True(crls.Contains(SignCrl));

            //
            // try using existing signer
            //

            gen = new CmsSignedDataGenerator();

            gen.AddSigners(s.GetSignerInfos());

            gen.AddCertificates(s.GetCertificates());
            gen.AddCrls(s.GetCrls());

            s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();
            x509Crls = s.GetCrls();

            signers = s.GetSignerInfos();

            foreach (SignerInformation signer in signers.GetSigners())
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            CheckSignerStoreReplacement(s, signers);
        }

        private static void EncapsulatedTest(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string digestAlgorithm)
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(signatureCert, OrigCert);
            var x509Crls = CmsTestUtil.MakeCrlStore(SignCrl);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(signaturePair.Private, signatureCert, digestAlgorithm);
            gen.AddCertificates(x509Certs);
            gen.AddCrls(x509Crls);

            CmsSignedData s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();
            x509Crls = s.GetCrls();

            SignerInformationStore signers = s.GetSignerInfos();
            var c = signers.GetSigners();

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.AreEqual(digestAlgorithm, signer.DigestAlgorithmID.Algorithm.GetID());

                Assert.True(signer.Verify(cert));
            }

            //
            // check for CRLs
            //
            var crls = new List<X509Crl>(x509Crls.EnumerateMatches(null));

            Assert.AreEqual(1, crls.Count);

            Assert.True(crls.Contains(SignCrl));

            //
            // try using existing signer
            //

            gen = new CmsSignedDataGenerator();

            gen.AddSigners(s.GetSignerInfos());

            gen.AddCertificates(s.GetCertificates());
            gen.AddCrls(s.GetCrls());

            s = gen.Generate(msg, true);

            s = new CmsSignedData(s.GetEncoded());

            x509Certs = s.GetCertificates();
            x509Crls = s.GetCrls();

            signers = s.GetSignerInfos();
            c = signers.GetSigners();

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            CheckSignerStoreReplacement(s, signers);
        }

        private static void DetachedTest(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string signatureAlgorithm, DerObjectIdentifier sigAlgOid)
        {
            DetachedTest(signaturePair, signatureCert, signatureAlgorithm, sigAlgOid, null);
        }

        private static void DetachedTest(AsymmetricCipherKeyPair signaturePair, X509Certificate signatureCert,
            string signatureAlgorithm, DerObjectIdentifier sigAlgOid, AlgorithmIdentifier expectedDigAlgID)
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(signatureCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();

            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory(signatureAlgorithm, signaturePair.Private), signatureCert));

            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(msg);

            s = new CmsSignedData(msg, s.GetEncoded());

            var digestAlgorithms = new HashSet<AlgorithmIdentifier>(s.GetDigestAlgorithms());
            Assert.Greater(digestAlgorithms.Count, 0);

            if (expectedDigAlgID != null)
            {
                Assert.True(digestAlgorithms.Contains(expectedDigAlgID));
            }

            x509Certs = s.GetCertificates();

            SignerInformationStore signers = s.GetSignerInfos();

            foreach (SignerInformation signer in signers.GetSigners())
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                if (sigAlgOid != null)
                {
                    Assert.AreEqual(sigAlgOid, signer.SignatureAlgorithm.Algorithm);
                    if (NoParams.Contains(sigAlgOid))
                    {
                        Assert.Null(signer.SignatureAlgorithm.Parameters);
                    }
                    else
                    {
                        Assert.AreEqual(DerNull.Instance, signer.SignatureAlgorithm.Parameters);
                    }
                }

                digestAlgorithms.Remove(signer.DigestAlgorithmID);

                Assert.True(signer.Verify(cert));
            }

            Assert.AreEqual(0, digestAlgorithms.Count);

            //
            // check signer information lookup
            //

            // TODO[cms] Need equivalent constructor/helper
            //SignerId sid = new JcaSignerId(signatureCert);
            SignerID signerID;
            {
                var issuerAndSerialNumber = new Asn1.Cms.IssuerAndSerialNumber(signatureCert.CertificateStructure);

                signerID = new SignerID()
                {
                    Issuer = issuerAndSerialNumber.Issuer,
                    SerialNumber = issuerAndSerialNumber.SerialNumber.Value,
                };
            }

            var collection = signers.GetSigners(signerID);

            Assert.AreEqual(1, collection.Count);
            Assert.NotNull(collection[0]);

            //
            // try using existing signer
            //

            gen = new CmsSignedDataGenerator();

            gen.AddSigners(s.GetSignerInfos());

            gen.AddCertificates(s.GetCertificates());

            s = gen.Generate(msg);

            s = new CmsSignedData(msg, s.GetEncoded());

            x509Certs = s.GetCertificates();

            signers = s.GetSignerInfos();

            foreach (SignerInformation signer in signers.GetSigners())
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }

            CheckSignerStoreReplacement(s, signers);
        }

        //
        // signerInformation store replacement test.
        //
        private static void CheckSignerStoreReplacement(CmsSignedData orig, SignerInformationStore signers)
        {
            CmsSignedData s = CmsSignedData.ReplaceSigners(orig, signers);

            var x509Certs = s.GetCertificates();

            signers = s.GetSignerInfos();
            var c = signers.GetSigners();

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;

                Assert.True(signer.Verify(cert));
            }
        }

        [Test]
        public void TestUnsortedAttributes()
        {
            CmsSignedData s = new CmsSignedData(new CmsProcessableByteArray(disorderedMessage), disorderedSet);

            var x509Certs = s.GetCertificates();

            SignerInformationStore signers = s.GetSignerInfos();
            var c = signers.GetSigners();

            foreach (SignerInformation signer in c)
            {
                var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

                var certEnum = certCollection.GetEnumerator();

                certEnum.MoveNext();
                X509Certificate cert = certEnum.Current;
                SignerInformation sAsIs = new AsIsSignerInformation(signer);

                Assert.False(signer.Verify(cert));
                Assert.True(sAsIs.Verify(cert));
            }
        }

        [Test]
        public void TestNullContentWithSigner()
        {
            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(null, false);

            s = new CmsSignedData(s.GetEncoded());

            VerifySignatures(s);
        }

        [Test]
        public void TestWithAttributeCertificate()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(SignDsaCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            var attrCert = CmsTestUtil.GetAttributeCertificate();

            var store = CmsTestUtil.MakeAttrCertStore(attrCert);

            gen.AddAttributeCertificates(store);

            CmsSignedData sd = gen.Generate(msg);

            Assert.AreEqual(4, sd.Version);

            store = sd.GetAttributeCertificates();

            var coll = new List<X509V2AttributeCertificate>(store.EnumerateMatches(null));

            Assert.AreEqual(1, coll.Count);

            Assert.True(coll.Contains(attrCert));

            //
            // create new certstore
            //
            x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            //
            // replace certs
            //
            sd = CmsSignedData.ReplaceCertificatesAndCrls(sd, x509Certs, null, null);

            VerifySignatures(sd);
        }

        [Test]
        public void TestCertStoreReplacement()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(SignDsaCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            CmsSignedData sd = gen.Generate(msg);

            //
            // create new certstore
            //
            x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            //
            // replace certs
            //
            sd = CmsSignedData.ReplaceCertificatesAndCrls(sd, x509Certs, null, null);

            VerifySignatures(sd);
        }

        [Test]
        public void TestEncapsulatedCertStoreReplacement()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(SignDsaCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            CmsSignedData sd = gen.Generate(msg, true);

            //
            // create new certstore
            //
            x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            //
            // replace certs
            //
            sd = CmsSignedData.ReplaceCertificatesAndCrls(sd, x509Certs, null, null);

            VerifySignatures(sd);
        }

        [Test]
        public void TestCertOrdering1()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert, SignDsaCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            CmsSignedData sd = gen.Generate(msg, true);

            x509Certs = sd.GetCertificates();
            var a = new List<X509Certificate>(x509Certs.EnumerateMatches(null));

            Assert.AreEqual(3, a.Count);
            Assert.AreEqual(OrigCert, a[0]);
            Assert.AreEqual(SignCert, a[1]);
            Assert.AreEqual(SignDsaCert, a[2]);
        }

        [Test]
        public void TestCertOrdering2()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(SignCert, SignDsaCert, OrigCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            CmsSignedData sd = gen.Generate(msg, true);

            x509Certs = sd.GetCertificates();
            var a = new List<X509Certificate>(x509Certs.EnumerateMatches(null));

            Assert.AreEqual(3, a.Count);
            Assert.AreEqual(SignCert, a[0]);
            Assert.AreEqual(SignDsaCert, a[1]);
            Assert.AreEqual(OrigCert, a[2]);
        }

        [Test]
        public void TestSignerStoreReplacement()
        {
            CmsProcessable msg = new CmsProcessableByteArray(Encoding.ASCII.GetBytes("Hello World!"));

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha1);
            gen.AddCertificates(x509Certs);

            CmsSignedData original = gen.Generate(msg, true);

            //
            // create new Signer
            //
            gen = new CmsSignedDataGenerator();
            gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedGenerator.DigestSha224);
            gen.AddCertificates(x509Certs);

            CmsSignedData newSD = gen.Generate(msg, true);

            //
            // replace signer
            //
            CmsSignedData sd = CmsSignedData.ReplaceSigners(original, newSD.GetSignerInfos());

            var signerEnum = sd.GetSignerInfos().GetSigners().GetEnumerator();
            signerEnum.MoveNext();
            SignerInformation signer = signerEnum.Current;

            Assert.AreEqual(NistObjectIdentifiers.IdSha224, signer.DigestAlgorithmID.Algorithm);

            // we use a parser here as it requires the digests to be correct in the digest set, if it
            // isn't we'll get a NullPointerException
            CmsSignedDataParser sp = new CmsSignedDataParser(sd.GetEncoded());

            sp.GetSignedContent().Drain();

            VerifySignatures(sp);
        }

        [Test]
        public void TestEncapsulatedSamples()
        {
            DoTestSample("PSSSignDataSHA1Enc.sig");
            DoTestSample("PSSSignDataSHA256Enc.sig");
            DoTestSample("PSSSignDataSHA512Enc.sig");
        }

        [Test]
        public void TestSamples()
        {
            DoTestSample("PSSSignData.data", "PSSSignDataSHA1.sig");
            DoTestSample("PSSSignData.data", "PSSSignDataSHA256.sig");
            DoTestSample("PSSSignData.data", "PSSSignDataSHA512.sig");
        }

        [Test]
        public void TestCounterSig()
        {
            CmsSignedData sig = new CmsSignedData(GetInput("counterSig.p7m"));

            SignerInformationStore ss = sig.GetSignerInfos();
            var signers = ss.GetSigners();

            SignerInformationStore cs = signers[0].GetCounterSignatures();
            var csSigners = cs.GetSigners();
            Assert.AreEqual(1, csSigners.Count);

            foreach (SignerInformation cSigner in csSigners)
            {
                var certCollection = new List<X509Certificate>(
                    sig.GetCertificates().EnumerateMatches(cSigner.SignerID));

                X509Certificate cert = (X509Certificate)certCollection[0];

                Assert.Null(cSigner.SignedAttributes[Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtContentType]);
                Assert.True(cSigner.Verify(cert));
            }

            VerifySignatures(sig);
        }

        [Test]
        public void TestEncryptionAlgECPublicKey()
        {
            byte[] sigBlock = Base64.Decode(
                "MIIEdwYJKoZIhvcNAQcCoIIEaDCCBGQCAQExDzANBglghkgBZQMEAgEFADAUBgkqhkiG9w" +
                "0BBwGgBwQFAQIDBAWgggMPMIIDCzCCAm6gAwIBAgIJALt88oa4pHaNMAkGByqGSM49BAEw" +
                "YzELMAkGA1UEBhMCR0ExCzAJBgNVBAgTAkFXMRAwDgYDVQQHEwdBdGxhbnRhMQwwCgYDVQ" +
                "QKEwNWTVcxDzANBgNVBAsTBkFXIEVNTTEWMBQGA1UEAxMNd3d3LmF3bWRtLmNvbTAeFw0x" +
                "NjA2MDgxNjQ2MTdaFw0xNjA3MDgxNjQ2MTdaMGMxCzAJBgNVBAYTAkdBMQswCQYDVQQIEw" +
                "JBVzEQMA4GA1UEBxMHQXRsYW50YTEMMAoGA1UEChMDVk1XMQ8wDQYDVQQLEwZBVyBFTU0x" +
                "FjAUBgNVBAMTDXd3dy5hd21kbS5jb20wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAAAlW" +
                "sasReERY0vzpm6WvDuznypGIyXfaf8Q/sieuHOdUxhzcMS8Gg4qxry9voSKozDn3vI1sFQ" +
                "3ZPxDgIouHSKZAA8G4aP72k/gQ7G8wnHx2DF+UgchfIL0GypTZqmjo0c7jb8ZDgklfGr+a" +
                "rFeL8gIVH+EqmUdJoYzBW0FX9RZmerjKOByDCBxTAdBgNVHQ4EFgQUHkakN+xGDRr7GCER" +
                "2OSy0FvvN7QwgZUGA1UdIwSBjTCBioAUHkakN+xGDRr7GCER2OSy0FvvN7ShZ6RlMGMxCz" +
                "AJBgNVBAYTAkdBMQswCQYDVQQIEwJBVzEQMA4GA1UEBxMHQXRsYW50YTEMMAoGA1UEChMD" +
                "Vk1XMQ8wDQYDVQQLEwZBVyBFTU0xFjAUBgNVBAMTDXd3dy5hd21kbS5jb22CCQC7fPKGuK" +
                "R2jTAMBgNVHRMEBTADAQH/MAkGByqGSM49BAEDgYsAMIGHAkIByvkebPlDlHVbZT+G+beF" +
                "DwBzuSbTLp5cae0R+qUxbd24sXD5wozRiMs3GVRGd7L0sDeHbq8iJrLrKv7UJuh7HqECQV" +
                "JVwthEuknri/pIajiuolJodLgVnaTqcCaOshuMejK1qT38yCqX/G5W/STw6iBv1/Dg6pwa" +
                "IsmtrTn3NMDZkH+1MYIBIzCCAR8CAQEwcDBjMQswCQYDVQQGEwJHQTELMAkGA1UECBMCQV" +
                "cxEDAOBgNVBAcTB0F0bGFudGExDDAKBgNVBAoTA1ZNVzEPMA0GA1UECxMGQVcgRU1NMRYw" +
                "FAYDVQQDEw13d3cuYXdtZG0uY29tAgkAu3zyhrikdo0wDQYJYIZIAWUDBAIBBQAwCwYHKo" +
                "ZIzj0CAQUABIGLMIGIAkIAth4AncbHuAVpUqiie/nY3E/2jarczGI4HfMHci4a+yLbsMaA" +
                "fU6baty0Ei6VUCWX7je5dmV/wb1gcU0RogDu9AwCQgFuI0qfrnXiC8Rfir7PpYl66P6eD7" +
                "bGT3XK+2UlfIO0N05yYZAaHu7jCIdHIhi1wwtq9dsHwpcEJhLlJ8LyifAxDw==");

            CmsSignedData signedData = new CmsSignedData(sigBlock);

            VerifySignatures(signedData);
        }

        [Test]
        public void TestForMultipleCounterSignatures()
        {
            CmsSignedData sd = new CmsSignedData(xtraCounterSig);

            foreach (SignerInformation sigI in sd.GetSignerInfos())
            {
                SignerInformationStore counter = sigI.GetCounterSignatures();
                Assert.AreEqual(2, counter.Count);

                var sigs = counter.GetSigners();
                Assert.AreEqual(2, sigs.Count);
            }
        }

        [Test]
        public void TestPkcs7SignedContent()
        {
            CmsSignedData sig = new CmsSignedData(GetInput("Pkcs7SignedContent.p7b"));

            VerifySignatures(sig);
        }

        [Test]
        public void TestSignerInfoGenCopyConstructor()
        {
            /*
             * NOTE: The point of this test in bc-java is to check that the SignerInfoGenerator "copy constructor"
             * actually copies everything into the new object (in particular the certificate was being missed).
             * bc-csharp only has the NewBuilder() method; the signatureFactory and certificate can't be included in the
             * builder since they are only arguments to the final Build call. Probably the way the builder works should
             * be overhauled so that Build() has no parameters, and everything from a SignerInfoGenerator can be copied
             * into it via a BuildCopy() method.
             */

            var sha256Signer = new Asn1SignatureFactory("SHA256withRSA", OrigKP.Private);

            SignerInfoGenerator signerInfoGen = new SignerInfoGeneratorBuilder().Build(sha256Signer, OrigCert);

            var signedAttrGen = new MyGenerator(signerInfoGen.SignedAttributeTableGenerator, signerInfoGen.Certificate);

            SignerInfoGenerator newSignerInfoGen = signerInfoGen.NewBuilder()
                .WithSignedAttributeGenerator(signedAttrGen)
                .Build(signerInfoGen.SignatureFactory, signerInfoGen.Certificate);

            Assert.AreSame(newSignerInfoGen.Certificate, signerInfoGen.Certificate);
            Assert.AreSame(newSignerInfoGen.UnsignedAttributeTableGenerator, signerInfoGen.UnsignedAttributeTableGenerator);
            Assert.AreSame(newSignerInfoGen.SignedAttributeTableGenerator, signedAttrGen);
        }

        // TODO There seems to be something reusable here; similar producers of IdAASigningCertificate(V2) elsewhere
        private class MyGenerator
            : CmsAttributeTableGenerator
        {
            private readonly CmsAttributeTableGenerator m_inner;
            private readonly X509Certificate m_certificate;

            internal MyGenerator(CmsAttributeTableGenerator inner, X509Certificate certificate)
            {
                m_inner = inner ?? throw new ArgumentNullException(nameof(inner));
                m_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            }

            public Asn1.Cms.AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
            {
                Asn1.Cms.AttributeTable table = m_inner.GetAttributes(parameters);

                if (table[Asn1.Pkcs.PkcsObjectIdentifiers.IdAASigningCertificateV2] != null)
                    return table;

                byte[] certHash256 = DigestUtilities.CalculateDigest("SHA256", m_certificate.GetEncoded());

                var c = m_certificate.CertificateStructure;
                var essCertIDv2 = new EssCertIDv2(certHash256, new IssuerSerial(c.Issuer, c.SerialNumber));
                var signingCertificateV2 = new SigningCertificateV2(essCertIDv2);

                return table.Add(Asn1.Pkcs.PkcsObjectIdentifiers.IdAASigningCertificateV2, signingCertificateV2);
            }
        }

        [Test]
        public void TestMsPkcs7()
        {
            var data = GetInput("Pkcs7SignedContent.p7b");
            var sData = new CmsSignedData(data);

            var certStore = sData.GetCertificates();
            var signers = sData.GetSignerInfos();
            var c = signers.GetSigners();

            foreach (var signer in c)
            {
                var certCollection = certStore.EnumerateMatches(signer.SignerID);
                foreach (var cert in certCollection)
                {
                    signer.Verify(cert);
                }
            }
        }

        [Test]
        public void VerifySignedDataMLDsa44()
        {
            ImplVerifySignedData(signedData_mldsa44, SampleCredentials.ML_DSA_44);
        }

        [Test]
        public void VerifySignedDataMLDsa65()
        {
            ImplVerifySignedData(signedData_mldsa65, SampleCredentials.ML_DSA_65);
        }

        [Test]
        public void VerifySignedDataMLDsa87()
        {
            ImplVerifySignedData(signedData_mldsa87, SampleCredentials.ML_DSA_87);
        }

        private static void DoTestSample(string sigName)
        {
            CmsSignedData sig = new CmsSignedData(GetInput(sigName));
            VerifySignatures(sig);
        }

        private static void DoTestSample(string messageName, string sigName)
        {
            CmsSignedData sig = new CmsSignedData(
                new CmsProcessableByteArray(GetInput(messageName)),
                GetInput(sigName));

            VerifySignatures(sig);
        }

        private static byte[] GetInput(string name) => SimpleTest.GetTestData("cms.sigs." + name);

        private static void ImplVerifySignedData(byte[] signedData, SampleCredentials credentials)
        {
            CmsSignedData sd = new CmsSignedData(signedData);

            // External signer verification
            {
                var signers = sd.GetSignerInfos();

                foreach (var signer in signers)
                {
                    // Verify using the certificate from the supplied credentials
                    Assert.True(signer.Verify(credentials.Certificate));
                }
            }

            // TODO Built-in signer verification (see bc-java)
        }

        private static void RsaDigestTest(string signatureAlgorithmName)
        {
            byte[] data = Encoding.ASCII.GetBytes("Hello World!");
            CmsProcessable msg = new CmsProcessableByteArray(data);

            var x509Certs = CmsTestUtil.MakeCertStore(OrigCert, SignCert);

            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory(signatureAlgorithmName, OrigKP.Private), OrigCert));
            gen.AddCertificates(x509Certs);

            CmsSignedData s = gen.Generate(msg, false);

            //
            // compute expected content digest
            //
            string digestName = signatureAlgorithmName.Substring(0, signatureAlgorithmName.IndexOf("with"));

            VerifySignatures(s, DigestUtilities.CalculateDigest(digestName, data));
        }

        private static void VerifyDirectSignatures(CmsSignedData s, byte[] contentDigest)
        {
            var x509Certs = s.GetCertificates();
            var signers = s.GetSignerInfos();

            foreach (var signer in signers)
            {
                var matches = x509Certs.EnumerateMatches(signer.SignerID);
                var cert = CollectionUtilities.GetFirstOrNull(matches);

                Assert.True(signer.Verify(cert));
                Assert.Null(signer.GetEncodedSignedAttributes());

                if (contentDigest != null)
                {
                    Assert.True(Arrays.AreEqual(contentDigest, signer.GetContentDigest()));
                }
            }
        }

        private static void VerifySignatures(CmsSignedData s) => VerifySignatures(s, null);

        private static void VerifySignatures(CmsSignedData s, byte[] contentDigest)
        {
            var x509Certs = s.GetCertificates();
            var signers = s.GetSignerInfos();

            foreach (var signer in signers)
            {
                var matches = x509Certs.EnumerateMatches(signer.SignerID);
                var cert = CollectionUtilities.GetFirstOrNull(matches);

                Assert.True(signer.Verify(cert));

                if (contentDigest != null)
                {
                    Assert.True(Arrays.AreEqual(contentDigest, signer.GetContentDigest()));
                }
            }
        }

        private static void VerifySignatures(CmsSignedDataParser sp)
        {
            var x509Certs = sp.GetCertificates();
            var signers = sp.GetSignerInfos();

            foreach (var signer in signers)
            {
                var matches = x509Certs.EnumerateMatches(signer.SignerID);
                var cert = CollectionUtilities.GetFirstOrNull(matches);

                Assert.True(signer.Verify(cert));
                Assert.True(new MySignerInformation(signer).Verify(cert)); // test simple copy works
            }
        }

        private class AsIsSignerInformation
            : SignerInformation
        {
            public AsIsSignerInformation(SignerInformation sInfo)
                : base(sInfo)
            {
            }

            public override byte[] GetEncodedSignedAttributes() => signedAttributeSet?.GetEncoded();
        }

        private class MySignerInformation
            : SignerInformation
        {
            public MySignerInformation(SignerInformation sigInf)
                : base(sigInf)
            {
            }
        }
    }
}
