using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
    [Parallelizable(ParallelScope.All)]
    public class EnvelopedDataTest
    {
        private const string SignDN = "O=Bouncy Castle, C=AU";

        private static AsymmetricCipherKeyPair signKP;
        private static X509Certificate signCert;

        private const string OrigDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";

        private static AsymmetricCipherKeyPair origKP;
        private static X509Certificate origCert;

        private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
        private const string ReciDN2 = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";

        private static AsymmetricCipherKeyPair reciKP;
        private static X509Certificate reciCert;

        private static AsymmetricCipherKeyPair reciKP_2048;
        private static X509Certificate reciCert_2048;

        private static AsymmetricCipherKeyPair origECKP;
        private static AsymmetricCipherKeyPair reciECKP;
        private static X509Certificate reciECCert;
        private static AsymmetricCipherKeyPair reciECKP2;
        private static X509Certificate reciECCert2;
        private static AsymmetricCipherKeyPair reciMLKem512KP;
        private static X509Certificate reciMLKem512Cert;
        private static AsymmetricCipherKeyPair reciMLKem768KP;
        private static X509Certificate reciMLKem768Cert;
        private static AsymmetricCipherKeyPair reciMLKem1024KP;
        private static X509Certificate reciMLKem1024Cert;

        private static AsymmetricCipherKeyPair OrigECKP =>
            CmsTestUtil.InitKP(ref origECKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair OrigKP => CmsTestUtil.InitKP(ref origKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair ReciKP => CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair ReciKP_2048 => CmsTestUtil.InitKP(ref reciKP_2048, CmsTestUtil.MakeKeyPair_2048);

        private static AsymmetricCipherKeyPair ReciECKP =>
            CmsTestUtil.InitKP(ref reciECKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair ReciMLKem512KP =>
            CmsTestUtil.InitKP(ref reciMLKem512KP, CmsTestUtil.MakeMLKem512KeyPair);

        private static AsymmetricCipherKeyPair ReciMLKem768KP =>
            CmsTestUtil.InitKP(ref reciMLKem768KP, CmsTestUtil.MakeMLKem768KeyPair);

        private static AsymmetricCipherKeyPair ReciMLKem1024KP =>
            CmsTestUtil.InitKP(ref reciMLKem1024KP, CmsTestUtil.MakeMLKem1024KeyPair);

        private static AsymmetricCipherKeyPair ReciECKP2 =>
            CmsTestUtil.InitKP(ref reciECKP2, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair SignKP => CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

        private static X509Certificate OrigCert => CmsTestUtil.InitCertificate(ref origCert,
            () => CmsTestUtil.MakeCertificate(OrigKP, OrigDN, SignKP, SignDN));

        private static X509Certificate ReciCert => CmsTestUtil.InitCertificate(ref reciCert,
            () => CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciCert_2048 => CmsTestUtil.InitCertificate(ref reciCert_2048,
            () => CmsTestUtil.MakeCertificate(ReciKP_2048, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciECCert => CmsTestUtil.InitCertificate(ref reciECCert,
            () => CmsTestUtil.MakeCertificate(ReciECKP, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciECCert2 => CmsTestUtil.InitCertificate(ref reciECCert2,
            () => CmsTestUtil.MakeCertificate(ReciECKP2, ReciDN2, SignKP, SignDN));

        private static X509Certificate ReciMLKem512Cert => CmsTestUtil.InitCertificate(ref reciMLKem512Cert,
            () => CmsTestUtil.MakeCertificate(ReciMLKem512KP, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciMLKem768Cert => CmsTestUtil.InitCertificate(ref reciMLKem768Cert,
            () => CmsTestUtil.MakeCertificate(ReciMLKem768KP, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciMLKem1024Cert => CmsTestUtil.InitCertificate(ref reciMLKem1024Cert,
            () => CmsTestUtil.MakeCertificate(ReciMLKem1024KP, ReciDN, SignKP, SignDN));

        private static X509Certificate SignCert => CmsTestUtil.InitCertificate(ref signCert,
            () => CmsTestUtil.MakeCertificate(SignKP, SignDN, SignKP, SignDN));

        private static readonly byte[] oldKEK = Base64.Decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxQaI/MD0CAQQwBwQFAQIDBAUwDQYJYIZIAWUDBAEFBQAEI"
            + "Fi2eHTPM4bQSjP4DUeDzJZLpfemW2gF1SPq7ZPHJi1mMIAGCSqGSIb3DQEHATAUBggqhkiG9w"
            + "0DBwQImtdGyUdGGt6ggAQYk9X9z01YFBkU7IlS3wmsKpm/zpZClTceAAAAAAAAAAAAAA==");

        private static readonly byte[] ecKeyAgreeMsgAES256 = Base64.Decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxgcShgcECAQOgQ6FBMAsGByqGSM49AgEF"
            + "AAMyAAPdXlSTpub+qqno9hUGkUDl+S3/ABhPziIB5yGU4678tgOgU5CiKG9Z"
            + "kfnabIJ3nZYwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBLQUAMFswWTAtMCgx"
            + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBCi/"
            + "rJRLbFwEVW6PcLLmojjW9lI/xGD7CfZzXrqXFw8iHaf3hTRau1gYMIAGCSqG"
            + "SIb3DQEHATAdBglghkgBZQMEASoEEMtCnKKPwccmyrbgeSIlA3qggAQQDLw8"
            + "pNJR97bPpj6baG99bQQQwhEDsoj5Xg1oOxojHVcYzAAAAAAAAAAAAAA=");

        private static readonly byte[] ecKeyAgreeMsgAES128 = Base64.Decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxgbShgbECAQOgQ6FBMAsGByqGSM49AgEF"
            + "AAMyAAL01JLEgKvKh5rbxI/hOxs/9WEezMIsAbUaZM4l5tn3CzXAN505nr5d"
            + "LhrcurMK+tAwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBBQUAMEswSTAtMCgx"
            + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBBhi"
            + "FLjc5g6aqDT3f8LomljOwl1WTrplUT8wgAYJKoZIhvcNAQcBMB0GCWCGSAFl"
            + "AwQBAgQQzXjms16Y69S/rB0EbHqRMaCABBAFmc/QdVW6LTKdEy97kaZzBBBa"
            + "fQuviUS03NycpojELx0bAAAAAAAAAAAAAA==");

        private static readonly byte[] ecKeyAgreeMsgDESEDE = Base64.Decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxgcahgcMCAQOgQ6FBMAsGByqGSM49AgEF"
            + "AAMyAALIici6Nx1WN5f0ThH2A8ht9ovm0thpC5JK54t73E1RDzCifePaoQo0"
            + "xd6sUqoyGaYwHAYJK4EFEIZIPwACMA8GCyqGSIb3DQEJEAMGBQAwWzBZMC0w"
            + "KDETMBEGA1UEAxMKQWRtaW4tTURTRTERMA8GA1UEChMINEJDVC0ySUQCAQEE"
            + "KJuqZQ1NB1vXrKPOnb4TCpYOsdm6GscWdwAAZlm2EHMp444j0s55J9wwgAYJ"
            + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAjwnsDMsafCrKCABBjyPvqFOVMKxxut"
            + "VfTx4fQlNGJN8S2ATRgECMcTQ/dsmeViAAAAAAAAAAAAAA==");

        private static readonly byte[] ecMqvKeyAgreeMsgAes128 = Base64.Decode(
              "MIAGCSqGSIb3DQEHA6CAMIACAQIxgf2hgfoCAQOgQ6FBMAsGByqGSM49AgEF"
            + "AAMyAAPDKU+0H58tsjpoYmYCInMr/FayvCCkupebgsnpaGEB7qS9vzcNVUj6"
            + "mrnmiC2grpmhRwRFMEMwQTALBgcqhkjOPQIBBQADMgACZpD13z9c7DzRWx6S"
            + "0xdbq3S+EJ7vWO+YcHVjTD8NcQDcZcWASW899l1PkL936zsuMBoGCSuBBRCG"
            + "SD8AEDANBglghkgBZQMEAQUFADBLMEkwLTAoMRMwEQYDVQQDEwpBZG1pbi1N"
            + "RFNFMREwDwYDVQQKEwg0QkNULTJJRAIBAQQYFq58L71nyMK/70w3nc6zkkRy"
            + "RL7DHmpZMIAGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEDzRUpreBsZXWHBe"
            + "onxOtSmggAQQ7csAZXwT1lHUqoazoy8bhAQQq+9Zjj8iGdOWgyebbfj67QAA"
            + "AAAAAAAAAAA=");

        private static readonly byte[] ecKeyAgreeKey = Base64.Decode(
            "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC8vp7xVTbKSgYVU5Wc"
            + "hGkWbzaj+yUFETIWP1Dt7+WSpq3ikSPdl7PpHPqnPVZfoIWhZANiAgSYHTgxf+Dd"
            + "Tt84dUvuSKkFy3RhjxJmjwIscK6zbEUzKhcPQG2GHzXhWK5x1kov0I74XpGhVkya"
            + "ElH5K6SaOXiXAzcyNGggTOk4+ZFnz5Xl0pBje3zKxPhYu0SnCw7Pcqw=");

        /*
         * OpenSSL 3.5.7 vectors (issue #697): 'openssl cms -encrypt -recip cert.pem [-keyopt ecdh_kdf_md:sha256]'.
         * The AES key-wrap AlgorithmIdentifier has absent parameters (RFC 5753 section 7.2), whereas the older
         * vectors above carry an explicit NULL; both encodings must be fed to the KDF exactly as received.
         */
        private static readonly byte[] openSslEcKeyAgreeKey = Base64.Decode(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLesokEE5JasY"
            + "ZBoFs6rNWYCVUaURjSUQzHWgytyzJvmhRANCAARvb4l75aHUwO2gvQ1ESrvz"
            + "p1JzhPbnocH1Y8RxS73or+uYTrBGcq5krg3fRHR9ySSvejDWpzl1yFhnnimZ"
            + "tn6Z");

        private static readonly byte[] openSslEcKeyAgreeMsgAes128Sha1 = Base64.Decode(
            "MIIBOwYJKoZIhvcNAQcDoIIBLDCCASgCAQIxgdShgdECAQOgUaFPMAkGByqG"
            + "SM49AgEDQgAElF/audNFif621SsmUm3MQ7NQTT9UlybminWyiwl57D74JMnq"
            + "YkjOPaa8+VK4wk74JEnYOz4sDTrNbWJ/LAGTgTAYBgkrgQUQhkg/AAIwCwYJ"
            + "YIZIAWUDBAEFMF8wXTBBMCkxFTATBgNVBAMMDFJlY2lwaWVudCBFQzEQMA4G"
            + "A1UECgwHQkMgVGVzdAIURCSGxBL9K7iK8eNRXi+jP/utRmgEGLF/QlMQJDDu"
            + "ClWalDlfGDOXiCqPpwGkAjBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAECBBAX"
            + "69KgBjXOm9LymN2V9xtEgCAHimqhcl4gDMg/GD12vjGhmg1kgQw9W6YvqHej"
            + "UEH7DA==");

        private static readonly byte[] openSslEcKeyAgreeMsgAes256Sha1 = Base64.Decode(
            "MIIBSwYJKoZIhvcNAQcDoIIBPDCCATgCAQIxgeShgeECAQOgUaFPMAkGByqG"
            + "SM49AgEDQgAE5u4V2aioW1PnhabaCESQOd/GdncNWnlsiZliIKXdiYgZyduq"
            + "xUVsBZuEF5epgXdseBGyQ5GZvcCkr5Fj6FqbXTAYBgkrgQUQhkg/AAIwCwYJ"
            + "YIZIAWUDBAEtMG8wbTBBMCkxFTATBgNVBAMMDFJlY2lwaWVudCBFQzEQMA4G"
            + "A1UECgwHQkMgVGVzdAIURCSGxBL9K7iK8eNRXi+jP/utRmgEKKEMhXG914Mq"
            + "b110s1iZB6SiAanVYIqTx/YmgfOSirl/EG3uP+5faI8wTAYJKoZIhvcNAQcB"
            + "MB0GCWCGSAFlAwQBKgQQoiiAk5KOIO/jY5gypLwtO4AgDJGCMyW9frblygQZ"
            + "vrOm52cIJRLmCVTqJ5lvWKuNrMU=");

        private static readonly byte[] openSslEcKeyAgreeMsgAes256Sha256 = Base64.Decode(
            "MIIBSAYJKoZIhvcNAQcDoIIBOTCCATUCAQIxgeGhgd4CAQOgUaFPMAkGByqG"
            + "SM49AgEDQgAEoFw91DrFroiZqY36p+mxEiTT6/fDFnEnYeG6+Qh4JiEgqDgn"
            + "PfTkdg3zzF0ZWmAWrLc0hescWwWAjcJXT4edKzAVBgYrgQQBCwEwCwYJYIZI"
            + "AWUDBAEtMG8wbTBBMCkxFTATBgNVBAMMDFJlY2lwaWVudCBFQzEQMA4GA1UE"
            + "CgwHQkMgVGVzdAIURCSGxBL9K7iK8eNRXi+jP/utRmgEKP5xILAFKJlVOQsf"
            + "xBRnKaPR5E+7Mab2TNOTJ9PW+DgH/9JmS4EQqAIwTAYJKoZIhvcNAQcBMB0G"
            + "CWCGSAFlAwQBKgQQF+lbB3ktPTi4WVhZpbJhpYAgtyu81F7Wqa1FyCDNSDic"
            + "32VAbY3kCEaBMJBXPQjpe5o=");

        private static readonly byte[] openSslEcKeyAgreeMsgDesEde3Sha1 = Base64.Decode(
            "MIIBRgYJKoZIhvcNAQcDoIIBNzCCATMCAQIxgeihgeUCAQOgUaFPMAkGByqG"
            + "SM49AgEDQgAESAURNoIYftZ/jSFmnhxspo2v+uKoqBfp/37yb7z08bnRIF+X"
            + "WjfdtOTN+usvF6tinTW1fQVyx3eXztFViK88ezAcBgkrgQUQhkg/AAIwDwYL"
            + "KoZIhvcNAQkQAwYFADBvMG0wQTApMRUwEwYDVQQDDAxSZWNpcGllbnQgRUMx"
            + "EDAOBgNVBAoMB0JDIFRlc3QCFEQkhsQS/Su4ivHjUV4voz/7rUZoBCj8X9cL"
            + "0Zb+BsVozQZpVqT2QjpIgDR8XlYy6o6iy4Vu/huau11OWJt2MEMGCSqGSIb3"
            + "DQEHATAUBggqhkiG9w0DBwQIaJ7bD3T4fPGAIK5HgrdamCCPZMaqLLwJj544"
            + "hyCwlZdZuYgM6Wd1moS9");

        /*
         * Messages produced by bc-csharp before 2.8.0 for the OpenSSL key above (issue #697). The AES key-wrap
         * AlgorithmIdentifier is encoded with absent parameters, but the KEK was derived as though it carried NULL,
         * so they can only be read via the CmsAllowLegacyKeyAgreeKdf retry.
         */
        private static readonly byte[] legacyEcKeyAgreeMsgAes128Sha1 = Base64.Decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxgd6hgdsCAQOgW6FZMBMGByqGSM49AgEG"
            + "CCqGSM49AwEHA0IABPos+V3W2/idEF3r+P8d0lvedlW4pUjr1OLgDebSER4/"
            + "X1Rr7L3eI08PaFVQwflh7EzuwvhoI49EXG8XsGb3exowGAYJK4EFEIZIPwAC"
            + "MAsGCWCGSAFlAwQBBTBfMF0wQTApMRUwEwYDVQQDDAxSZWNpcGllbnQgRUMx"
            + "EDAOBgNVBAoMB0JDIFRlc3QCFEQkhsQS/Su4ivHjUV4voz/7rUZoBBjNyN5y"
            + "F0/tewrc7skuhvaFzdxBj8PkIxUwgAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQB"
            + "AgQQZLz6u/MhPUFNIvQsnUpgcYAgNaoXccdd5BjexnYPIfRr6LurA9jJebbN"
            + "2+BIHDtSXUQAAAAAAAAAAA==");

        private static readonly byte[] legacyEcKeyAgreeMsgAes256Sha256 = Base64.Decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxgeuhgegCAQOgW6FZMBMGByqGSM49AgEG"
            + "CCqGSM49AwEHA0IABPos+V3W2/idEF3r+P8d0lvedlW4pUjr1OLgDebSER4/"
            + "X1Rr7L3eI08PaFVQwflh7EzuwvhoI49EXG8XsGb3exowFQYGK4EEAQsBMAsG"
            + "CWCGSAFlAwQBLTBvMG0wQTApMRUwEwYDVQQDDAxSZWNpcGllbnQgRUMxEDAO"
            + "BgNVBAoMB0JDIFRlc3QCFEQkhsQS/Su4ivHjUV4voz/7rUZoBCjrQas6b0fA"
            + "Kdti8tbD7X9GZ1TVGsJ7Vf/6tFi1vxUeLJI3b3IO6m9mMIAGCSqGSIb3DQEH"
            + "ATAdBglghkgBZQMEASoEEOvoEj9BfCFEi7Pv1WOX5YOAIKaSzpFcCUCWDuTL"
            + "8jv3whm3iSPWwjDTUe9/Ve22lxd0AAAAAAAAAAA=");

        /*
         * User keying material for the key agreement ukm tests. The bc-test-data messages were produced by bc-java
         * (JceKeyAgreeRecipientInfoGenerator.setUserKeyingMaterial; 1.86 for ECDH, 1.87 for ECMQV) with this ukm,
         * each with a fresh P-256 originator key, for the recipient key in recipient_p256.pem.
         */
        private static readonly byte[] keyAgreeUkm = Hex.Decode("6a7e1b2c3d4f5061728394a5b6c7d8e9");

        private const string EcdhUkmVectorsPath = "pkix/cms/ecdh-ukm";
        private const string MqvUkmVectorsPath = "pkix/cms/mqv-ukm";

        /*
         * Not conformance vectors: ECMQV messages from bc-java 1.53 to 1.86, which gave the KDF the raw addedukm
         * (or nothing) as its SharedInfo instead of the DER-encoded ECC-CMS-SharedInfo.
         */
        private const string MqvLegacyKdfVectorsPath = "pkix/cms/mqv-legacy-kdf";

        private static readonly byte[] bobPrivRsaEncrypt = Base64.Decode(
            "MIIChQIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKnhZ5g/OdVf"
            + "8qCTQV6meYmFyDVdmpFb+x0B2hlwJhcPvaUi0DWFbXqYZhRBXM+3twg7CcmR"
            + "uBlpN235ZR572akzJKN/O7uvRgGGNjQyywcDWVL8hYsxBLjMGAgUSOZPHPtd"
            + "YMTgXB9T039T2GkB8QX4enDRvoPGXzjPHCyqaqfrAgMBAAECgYBnzUhMmg2P"
            + "mMIbZf8ig5xt8KYGHbztpwOIlPIcaw+LNd4Ogngwy+e6alatd8brUXlweQqg"
            + "9P5F4Kmy9Bnah5jWMIR05PxZbMHGd9ypkdB8MKCixQheIXFD/A0HPfD6bRSe"
            + "TmPwF1h5HEuYHD09sBvf+iU7o8AsmAX2EAnYh9sDGQJBANDDIsbeopkYdo+N"
            + "vKZ11mY/1I1FUox29XLE6/BGmvE+XKpVC5va3Wtt+Pw7PAhDk7Vb/s7q/WiE"
            + "I2Kv8zHCueUCQQDQUfweIrdb7bWOAcjXq/JY1PeClPNTqBlFy2bKKBlf4hAr"
            + "84/sajB0+E0R9KfEILVHIdxJAfkKICnwJAiEYH2PAkA0umTJSChXdNdVUN5q"
            + "SO8bKlocSHseIVnDYDubl6nA7xhmqU5iUjiEzuUJiEiUacUgFJlaV/4jbOSn"
            + "I3vQgLeFAkEAni+zN5r7CwZdV+EJBqRd2ZCWBgVfJAZAcpw6iIWchw+dYhKI"
            + "FmioNRobQ+g4wJhprwMKSDIETukPj3d9NDAlBwJAVxhn1grStavCunrnVNqc"
            + "BU+B1O8BiR4yPWnLMcRSyFRVJQA7HCp8JlDV6abXd8vPFfXuC9WN7rOvTKF8"
            + "Y0ZB9qANMAsGA1UdDzEEAwIAEA==");

        private static readonly byte[] rfc4134ex5_1 = Base64.Decode(
            "MIIBHgYJKoZIhvcNAQcDoIIBDzCCAQsCAQAxgcAwgb0CAQAwJjASMRAwDgYD"
            + "VQQDEwdDYXJsUlNBAhBGNGvHgABWvBHTbi7NXXHQMA0GCSqGSIb3DQEBAQUA"
            + "BIGAC3EN5nGIiJi2lsGPcP2iJ97a4e8kbKQz36zg6Z2i0yx6zYC4mZ7mX7FB"
            + "s3IWg+f6KgCLx3M1eCbWx8+MDFbbpXadCDgO8/nUkUNYeNxJtuzubGgzoyEd"
            + "8Ch4H/dd9gdzTd+taTEgS0ipdSJuNnkVY4/M652jKKHRLFf02hosdR8wQwYJ"
            + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAgtaMXpRwZRNYAgDsiSf8Z9P43LrY4O"
            + "xUk660cu1lXeCSFOSOpOJ7FuVyU=");

        private static readonly byte[] rfc4134ex5_2 = Base64.Decode(
            "MIIBZQYJKoZIhvcNAQcDoIIBVjCCAVICAQIxggEAMIG9AgEAMCYwEjEQMA4G"
            + "A1UEAxMHQ2FybFJTQQIQRjRrx4AAVrwR024uzV1x0DANBgkqhkiG9w0BAQEF"
            + "AASBgJQmQojGi7Z4IP+CVypBmNFoCDoEp87khtgyff2N4SmqD3RxPx+8hbLQ"
            + "t9i3YcMwcap+aiOkyqjMalT03VUC0XBOGv+HYI3HBZm/aFzxoq+YOXAWs5xl"
            + "GerZwTOc9j6AYlK4qXvnztR5SQ8TBjlzytm4V7zg+TGrnGVNQBNw47Ewoj4C"
            + "AQQwDQQLTWFpbExpc3RSQzIwEAYLKoZIhvcNAQkQAwcCAToEGHcUr5MSJ/g9"
            + "HnJVHsQ6X56VcwYb+OfojTBJBgkqhkiG9w0BBwEwGgYIKoZIhvcNAwIwDgIC"
            + "AKAECJwE0hkuKlWhgCBeKNXhojuej3org9Lt7n+wWxOhnky5V50vSpoYRfRR"
            + "yw==");

        private static readonly byte[] gost2012_Sender_Cert = Base64.Decode(
            "MIIETDCCA/mgAwIBAgIEB/tRdzAKBggqhQMHAQEDAjCB0TELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MSgwJgYDVQQLDB/QlNC10LnRgdGC0LLRg9GO0YnQ" +
            "uNC1INC70LjRhtCwMS0wKwYDVQQMDCTQpNC40LvQvtGB0L7QsiDQuCDQv9GD0LHQu9C40YbQuNGB0YIxJjAkBgNVBAMMHdCV" +
            "0LLQs9C10L3RltC5INCe0L3Ro9Cz0LjQvdGKMB4XDTE3MDcxNTE0MDAwMFoXDTM3MDcxNTE0MDAwMFowgdExCzAJBgNVBAYT" +
            "AlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHRg9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEo" +
            "MCYGA1UECwwf0JTQtdC50YHRgtCy0YPRjtGJ0LjQtSDQu9C40YbQsDEtMCsGA1UEDAwk0KTQuNC70L7RgdC+0LIg0Lgg0L/R" +
            "g9Cx0LvQuNGG0LjRgdGCMSYwJAYDVQQDDB3QldCy0LPQtdC90ZbQuSDQntC90aPQs9C40L3RijBmMB8GCCqFAwcBAQEBMBMG" +
            "ByqFAwICJAAGCCqFAwcBAQICA0MABEAl9XE868NRYm3CQXCPO+BJlVi7kxORfoyRaHyWyKBFf4TYV4eEUF/WjAf3fAqsndp6" +
            "v1DNqa3KS1R1yqn1Ug4do4IBrjCCAaowDgYDVR0PAQH/BAQDAgH+MGMGA1UdJQRcMFoGCCsGAQUFBwMBBggrBgEFBQcDAgYI" +
            "KwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCAYIKwYBBQUHAwkwDwYD" +
            "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUzhoR/a0hWGOpy6GPEm7LBCJ3dLYwggEBBgNVHSMEgfkwgfaAFM4aEf2tIVhjqcuh" +
            "jxJuywQid3S2oYHXpIHUMIHRMQswCQYDVQQGEwJSVTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNV" +
            "BAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxKDAmBgNVBAsMH9CU0LXQudGB0YLQstGD0Y7RidC40LUg0LvQuNGG0LAxLTAr" +
            "BgNVBAwMJNCk0LjQu9C+0YHQvtCyINC4INC/0YPQsdC70LjRhtC40YHRgjEmMCQGA1UEAwwd0JXQstCz0LXQvdGW0Lkg0J7Q" +
            "vdGj0LPQuNC90YqCBAf7UXcwCgYIKoUDBwEBAwIDQQDcFDvbdfUu1087tslF70OeZgLW5QHRtPLUaldE9x1Geu2veJos9fZ7" +
            "nqISVcd1wrf6FfADt3Tw2pQuG8mVCNUi"
        );

        private static readonly byte[] gost2012_Sender_Key = Base64.Decode(
            "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgYARzlWBWAJLs64jQbYW4UEXqFN/ChtWCSHqRgivT" +
            "8Ds="
        );

        private static readonly byte[] gost2012_Reci_Cert = Base64.Decode(
            "MIIEMzCCA+CgAwIBAgIEe7X7RjAKBggqhQMHAQEDAjCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQ" +
            "stC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGA" +
            "INCh0LXRgNCz0LXQtdCy0LjRhzAeFw0xNzA3MTUxNDAwMDBaFw0zNzA3MTUxNDAwMDBaMIHJMQswCQYDVQQGEwJSVTEgMB4G" +
            "A1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxHzAdBgNVBAsM" +
            "FtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMMMtCf0YPRiNC60LjQ" +
            "vSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHMGYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEB" +
            "AgIDQwAEQGQ4aJ3On0XqEt62PUfquYCAx0690AzlyE9IO8r5zkNKldvK4THC1IgBHkRzKiewquMm0YuYh76NI01uNjThOjyj" +
            "ggGlMIIBoTAOBgNVHQ8BAf8EBAMCAf4wYwYDVR0lBFwwWgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUH" +
            "AwQGCCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMIBggrBgEFBQcDCTAPBgNVHRMBAf8EBTADAQH/MB0G" +
            "A1UdDgQWBBROPw+FggywJjV9aLLSKz2Cr0BD9zCB+QYDVR0jBIHxMIHugBROPw+FggywJjV9aLLSKz2Cr0BD96GBz6SBzDCB" +
            "yTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQ" +
            "tdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTsw" +
            "OQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRh4IEe7X7RjAKBggqhQMH" +
            "AQEDAgNBAJR6UhzmUlRzlbiCU8IjhrR15c2uFtcHqHaUfiO8XJ2bnOiwxADZbnqlN3Foul6QrTXa5Vu1UbA2hFobJeuDniQ="
        );

        private static readonly byte[] gost2012_Reci_Key = Base64.Decode(
            "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgbtgmrFxhZLQm9H1Gx0+BAVTP6ZVLu20KcmKNzdIh" +
            "rKc="
        );

        private static readonly byte[] gost2012_Reci_Msg = Base64.Decode(
            "MIICBgYJKoZIhvcNAQcDoIIB9zCCAfMCAQAxggGyoYIBrgIBA6BooWYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEB" +
            "AgIDQwAEQCX1cTzrw1FibcJBcI874EmVWLuTE5F+jJFofJbIoEV/hNhXh4RQX9aMB/d8Cqyd2nq/UM2prcpLVHXKqfVSDh2h" +
            "CgQIDIhh5975RYMwKgYIKoUDBwEBBgEwHgYHKoUDAgINATATBgcqhQMCAh8BBAgMiGHn3vlFgzCCAQUwggEBMIHSMIHJMQsw" +
            "CQYDVQQGEwJSVTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3Q" +
            "vdC40LoxHzAdBgNVBAsMFtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNV" +
            "BAMMMtCf0YPRiNC60LjQvSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHAgR7tftGBCowKAQgLMyx3zUe" +
            "56F7eAKUAezilo3fxp6M/E+YkVVUDgFadfcEBHMmXJMwOAYJKoZIhvcNAQcBMB0GBiqFAwICFTATBAhJHfyezbxrUQYHKoUD" +
            "AgIfAYAMLLM89stnSyrWGWSW"
        );

        private static readonly byte[] gost2012_512_Sender_Cert = Base64.Decode(
            "MIIE0jCCBD6gAwIBAgIEMBwU/jAKBggqhQMHAQEDAzCB0TELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MSgwJgYDVQQLDB/QlNC10LnRgdGC0LLRg9GO0YnQ" +
            "uNC1INC70LjRhtCwMS0wKwYDVQQMDCTQpNC40LvQvtGB0L7QsiDQuCDQv9GD0LHQu9C40YbQuNGB0YIxJjAkBgNVBAMMHdCV" +
            "0LLQs9C10L3RltC5INCe0L3Ro9Cz0LjQvdGKMB4XDTE3MDcxNTE0MDAwMFoXDTM3MDcxNTE0MDAwMFowgdExCzAJBgNVBAYT" +
            "AlJVMSAwHgYDVQQIDBfQoS7Qn9C40YLQtdGA0LHRg9GA0LPRijEfMB0GA1UECgwW0KHQvtCy0YDQtdC80LXQvdC90LjQujEo" +
            "MCYGA1UECwwf0JTQtdC50YHRgtCy0YPRjtGJ0LjQtSDQu9C40YbQsDEtMCsGA1UEDAwk0KTQuNC70L7RgdC+0LIg0Lgg0L/R" +
            "g9Cx0LvQuNGG0LjRgdGCMSYwJAYDVQQDDB3QldCy0LPQtdC90ZbQuSDQntC90aPQs9C40L3RijCBqjAhBggqhQMHAQEBAjAV" +
            "BgkqhQMHAQIBAgEGCCqFAwcBAQIDA4GEAASBgLnNMC1uA9NjhZMyIotCn+4H+iqcTv5paCYmRIuIvWZO7OvUv3u9aWK5Lb0w" +
            "CH2Imbg/ffZV84xSwbNST83w4IFh8u1mAnf302+uuqt62pBU3VtPOPt3RYRwEABSDuTlBP2VocXa2iP53HM09fxhS/AJ14eR" +
            "K2oJ4cNpASXDH1mSo4IBrjCCAaowDgYDVR0PAQH/BAQDAgH+MGMGA1UdJQRcMFoGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYB" +
            "BQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCAYIKwYBBQUHAwkwDwYDVR0T" +
            "AQH/BAUwAwEB/zAdBgNVHQ4EFgQUEImfPZM/dIJULOrK4d/vMchap9kwggEBBgNVHSMEgfkwgfaAFBCJnz2TP3SCVCzqyuHf" +
            "7zHIWqfZoYHXpIHUMIHRMQswCQYDVQQGEwJSVTEgMB4GA1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoM" +
            "FtCh0L7QstGA0LXQvNC10L3QvdC40LoxKDAmBgNVBAsMH9CU0LXQudGB0YLQstGD0Y7RidC40LUg0LvQuNGG0LAxLTArBgNV" +
            "BAwMJNCk0LjQu9C+0YHQvtCyINC4INC/0YPQsdC70LjRhtC40YHRgjEmMCQGA1UEAwwd0JXQstCz0LXQvdGW0Lkg0J7QvdGj" +
            "0LPQuNC90YqCBDAcFP4wCgYIKoUDBwEBAwMDgYEAKZRx05mBwO7VIzj1FFJcHlfbHuLF+XZbFZaVfWc32R+KLxBJ0t1RuQ34" +
            "KtjQhu8/oU2rR/pKcmyHRw3nxJy+DExdj7sWJ01uWH6vBa+nsXS8OzSIg+wb9hlrFy0wZSkQjyNMtSiNg+On1yzFeI2fxuAY" +
            "OtIKHdqht+V+6M0g8BA="
        );

        private static readonly byte[] gost2012_512_Sender_Key = Base64.Decode(
            "MGoCAQAwIQYIKoUDBwEBBgIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBEDYpenYz4GDc/sIGl34Cv1T4xtWDlt7FB28ghXT" +
            "n4MXm43IvLwW3YclZbRz7V9W5lR0XoftGJ9q3ICv/IN2F+Dr"
        );

        private static readonly byte[] gost2012_512_Reci_Cert = Base64.Decode(
            "MIIEuTCCBCWgAwIBAgIECpLweDAKBggqhQMHAQEDAzCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQ" +
            "stC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGA" +
            "INCh0LXRgNCz0LXQtdCy0LjRhzAeFw0xNzA3MTUxNDAwMDBaFw0zNzA3MTUxNDAwMDBaMIHJMQswCQYDVQQGEwJSVTEgMB4G" +
            "A1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxHzAdBgNVBAsM" +
            "FtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMMMtCf0YPRiNC60LjQ" +
            "vSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHMIGqMCEGCCqFAwcBAQECMBUGCSqFAwcBAgECAQYIKoUD" +
            "BwEBAgMDgYQABIGAnZAIQhH/2nmSIZWfn+K3ftHGWbx1vrh/IeA43Q/z7h9jVPcVV3Csju92lgL5cnXyBAV90CVGw0/bCu1N" +
            "CYUpC0EVx5OmTd54fqicmFgZLqEnX6sbCXvpgCdvXhyYl+h7PTGHcuwGsMXZlIKVQLq6quVKh/UI/IfGK5CcPkX0PVCjggGl" +
            "MIIBoTAOBgNVHQ8BAf8EBAMCAf4wYwYDVR0lBFwwWgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQG" +
            "CCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMIBggrBgEFBQcDCTAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud" +
            "DgQWBBRvBhSgd/YSnT1ldXAE2V92ksV6WzCB+QYDVR0jBIHxMIHugBRvBhSgd/YSnT1ldXAE2V92ksV6W6GBz6SBzDCByTEL" +
            "MAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC9" +
            "0L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYD" +
            "VQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRh4IECpLweDAKBggqhQMHAQED" +
            "AwOBgQDilJAjXm+OK+mkfOk2ij3qKj00+gyFzJbxtk8wKEG7QmvlOPQvywke1pmCh8b1Z48OFOdmfKnTLE/D4AI/MQECUb1h" +
            "ChUfgfrSw0LY205tqxp6aqDtc2iPI7XHQAKE+jD819zubjCBzVDOiyRXatiRsEtfXPTBvqQdisM4rSw+OQ=="
        );

        private static readonly byte[] gost2012_512_Reci_Key = Base64.Decode(
            "MGoCAQAwIQYIKoUDBwEBBgIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBEDbd6/MUJS1QjpkwGUCg8OtxzuxiU2qm2VDBDDN" +
            "ZQ8/GtO12OiysmJHAXS9fpO1TRuyySw0r5r4x2g0NCWtVdQf"
        );

        private static readonly byte[] gost2012_512_Reci_Msg = Base64.Decode(
            "MIICTAYJKoZIhvcNAQcDoIICPTCCAjkCAQAxggH4oYIB9AIBA6CBraGBqjAhBggqhQMHAQEBAjAVBgkqhQMHAQIBAgEGCCqF" +
            "AwcBAQIDA4GEAASBgLnNMC1uA9NjhZMyIotCn+4H+iqcTv5paCYmRIuIvWZO7OvUv3u9aWK5Lb0wCH2Imbg/ffZV84xSwbNS" +
            "T83w4IFh8u1mAnf302+uuqt62pBU3VtPOPt3RYRwEABSDuTlBP2VocXa2iP53HM09fxhS/AJ14eRK2oJ4cNpASXDH1mSoQoE" +
            "CGGh2agBkurNMCoGCCqFAwcBAQYCMB4GByqFAwICDQEwEwYHKoUDAgIfAQQIYaHZqAGS6s0wggEFMIIBATCB0jCByTELMAkG" +
            "A1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3Q" +
            "uNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQD" +
            "DDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhwIECpLweAQqMCgEIBEN53tKgcd9" +
            "VW9uczUiwSM0pS/a7/vKIvTIqnIR0E5pBAQ+WRdXMDgGCSqGSIb3DQEHATAdBgYqhQMCAhUwEwQIbDvPAW4Wm0UGByqFAwIC" +
            "HwGADFMeOJyH3t7YSNgxsA=="
        );

        private static readonly byte[] gost2012_KeyTrans_Reci_Cert = Base64.Decode(
            "MIIEMzCCA+CgAwIBAgIEBSqgszAKBggqhQMHAQEDAjCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQ" +
            "sdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQ" +
            "stC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGA" +
            "INCh0LXRgNCz0LXQtdCy0LjRhzAeFw0xNzA3MTYxNDAwMDBaFw0zNzA3MTYxNDAwMDBaMIHJMQswCQYDVQQGEwJSVTEgMB4G" +
            "A1UECAwX0KEu0J/QuNGC0LXRgNCx0YPRgNCz0YoxHzAdBgNVBAoMFtCh0L7QstGA0LXQvNC10L3QvdC40LoxHzAdBgNVBAsM" +
            "FtCg0YPQutC+0LLQvtC00YHRgtCy0L4xGTAXBgNVBAwMENCg0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMMMtCf0YPRiNC60LjQ" +
            "vSDQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHMGYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEB" +
            "AgIDQwAEQEG5/wUY0LkiqETYAZY6o5mrjwWQNBYbSIKghYgKzLgSv1RCuTEFXRIJQcMG0V80auKVZNty9kcvn9P0IcJpGfGj" +
            "ggGlMIIBoTAOBgNVHQ8BAf8EBAMCAf4wYwYDVR0lBFwwWgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUH" +
            "AwQGCCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMIBggrBgEFBQcDCTAPBgNVHRMBAf8EBTADAQH/MB0G" +
            "A1UdDgQWBBQJwiUIQOJNbB0Fzh6ucd3uRE9QzDCB+QYDVR0jBIHxMIHugBQJwiUIQOJNbB0Fzh6ucd3uRE9QzKGBz6SBzDCB" +
            "yTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQ" +
            "tdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTsw" +
            "OQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRh4IEBSqgszAKBggqhQMH" +
            "AQEDAgNBAKLmdCiVR9MWeoC+MNudXGny3l2uDBBttvhTli0gDEaQLnBFyvD+cfSLgsheoz8vwhyqD/6W3ATBMRiGjqNJjQE="
        );

        private static readonly byte[] gost2012_KeyTrans_Reci_Key = Base64.Decode(
            "MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgy+dPu0sLqJ/Fokomiu69lRA48HaPNkP7kmzDHOxP" +
            "QFc="
        );

        private static readonly byte[] gost2012_KeyTrans_Msg = Base64.Decode(
            "MIIB/gYJKoZIhvcNAQcDoIIB7zCCAesCAQAxggGqMIIBpgIBADCB0jCByTELMAkGA1UEBhMCUlUxIDAeBgNVBAgMF9ChLtCf" +
            "0LjRgtC10YDQsdGD0YDQs9GKMR8wHQYDVQQKDBbQodC+0LLRgNC10LzQtdC90L3QuNC6MR8wHQYDVQQLDBbQoNGD0LrQvtCy" +
            "0L7QtNGB0YLQstC+MRkwFwYDVQQMDBDQoNC10LTQsNC60YLQvtGAMTswOQYDVQQDDDLQn9GD0YjQutC40L0g0JDQu9C10LrR" +
            "gdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhwIEBSqgszAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgSBqjCB" +
            "pzAoBCBnHA+9wEUh7KIkYlboGbtxRfrTL1oPGU3Tzaw8/khaWgQE+N56jaB7BgcqhQMCAh8BoGYwHwYIKoUDBwEBAQEwEwYH" +
            "KoUDAgIkAAYIKoUDBwEBAgIDQwAEQMbb4wVWm1EWIIXKDseCNE6JHmS+4fNh2uB+10Isg7g8/1Wvdh66IFir6fyp8NRwwMkU" +
            "QM0dmAfcpN6M2RSj83wECMCTi+FRlTafMDgGCSqGSIb3DQEHATAdBgYqhQMCAhUwEwQIzZlyAleTrCEGByqFAwICHwGADIO7" +
            "l43OVnBpGM+FjQ=="
        );

        //[Test]
        //public void TestMLKem512()
        //{
        //    byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

        //    // Send response with encrypted certificate
        //    CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

        //    // note: use cert req ID as key ID, don't want to use issuer/serial in this case!
        //    edGen.AddKemRecipient( // ...or AddRecipientInfoGenerator?
        //        PkcsObjectIdentifiers.IdAlgHkdfWithSha256.GetID(),
        //        ReciMLKem512Cert,
        //        CmsEnvelopedGenerator.Aes128Wrap);

        //    CmsEnvelopedData ed = edGen.Generate(
        //        new CmsProcessableByteArray(data),
        //        CmsEnvelopedGenerator.Aes128Cbc);

        //    RecipientInformationStore recipients = ed.GetRecipientInfos();

        //    Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

        //    var c = recipients.GetRecipients();

        //    Assert.AreEqual(1, c.Count);

        //    int expectedLength = new DefaultKemEncapsulationLengthProvider().getEncapsulationLength(
        //        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ReciMLKem512KP.Public).Algorithm);

        //    foreach (KemRecipientInformation recipient in c)
        //    {
        //        Assert.AreEqual(expectedLength, recipient.GetEncapsulation().Length);

        //        Assert.AreEqual(NistObjectIdentifiers.id_alg_ml_kem_512.GetID(), recipient.KeyEncryptionAlgOid);

        //        CmsTypedStream contentStream = recipient.GetContentStream(ReciMLKem512KP.Private);

        //        Assert.AreEqual(PkcsObjectIdentifiers.Data.GetID(), contentStream.ContentType);
        //        Assert.True(Arrays.AreEqual(data, Streams.ReadAll(contentStream.ContentStream)));
        //    }
        //}

        //[Test]
        //public void TestMLKem768()
        //{
        //    byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

        //    // Send response with encrypted certificate
        //    CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

        //    // note: use cert req ID as key ID, don't want to use issuer/serial in this case!
        //    edGen.AddKemRecipient( // ...or AddRecipientInfoGenerator?
        //        PkcsObjectIdentifiers.IdAlgHkdfWithSha256.GetID(),
        //        ReciMLKem768Cert,
        //        CmsEnvelopedGenerator.Aes256Wrap);

        //    CmsEnvelopedData ed = edGen.Generate(
        //        new CmsProcessableByteArray(data),
        //        CmsEnvelopedGenerator.Aes256Cbc);

        //    RecipientInformationStore recipients = ed.GetRecipientInfos();

        //    Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes256Cbc);

        //    var c = recipients.GetRecipients();

        //    Assert.AreEqual(1, c.Count);

        //    int expectedLength = new DefaultKemEncapsulationLengthProvider().getEncapsulationLength(
        //        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ReciMLKem768KP.Public).Algorithm);

        //    foreach (KemRecipientInformation recipient in c)
        //    {
        //        Assert.AreEqual(expectedLength, recipient.GetEncapsulation().Length);

        //        Assert.AreEqual(NistObjectIdentifiers.id_alg_ml_kem_768.GetID(), recipient.KeyEncryptionAlgOid);

        //        CmsTypedStream contentStream = recipient.GetContentStream(ReciMLKem768KP.Private);

        //        Assert.AreEqual(PkcsObjectIdentifiers.Data.GetID(), contentStream.ContentType);
        //        Assert.True(Arrays.AreEqual(data, Streams.ReadAll(contentStream.ContentStream)));
        //    }
        //}

        //[Test]
        //public void TestMLKem1024()
        //{
        //    byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

        //    // Send response with encrypted certificate
        //    CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

        //    // note: use cert req ID as key ID, don't want to use issuer/serial in this case!
        //    edGen.AddKemRecipient( // ...or AddRecipientInfoGenerator?
        //        PkcsObjectIdentifiers.IdAlgHkdfWithSha256.GetID(),
        //        ReciMLKem1024Cert,
        //        CmsEnvelopedGenerator.Aes256Wrap);

        //    CmsEnvelopedData ed = edGen.Generate(
        //        new CmsProcessableByteArray(data),
        //        CmsEnvelopedGenerator.Aes256Cbc);

        //    RecipientInformationStore recipients = ed.GetRecipientInfos();

        //    Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes256Cbc);

        //    var c = recipients.GetRecipients();

        //    Assert.AreEqual(1, c.Count);

        //    int expectedLength = new DefaultKemEncapsulationLengthProvider().getEncapsulationLength(
        //        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ReciMLKem1024KP.Public).Algorithm);

        //    foreach (KemRecipientInformation recipient in c)
        //    {
        //        Assert.AreEqual(expectedLength, recipient.GetEncapsulation().Length);

        //        Assert.AreEqual(NistObjectIdentifiers.id_alg_ml_kem_1024.GetID(), recipient.KeyEncryptionAlgOid);

        //        CmsTypedStream contentStream = recipient.GetContentStream(ReciMLKem1024KP.Private);

        //        Assert.AreEqual(PkcsObjectIdentifiers.Data.GetID(), contentStream.ContentType);
        //        Assert.True(Arrays.AreEqual(data, Streams.ReadAll(contentStream.ContentStream)));
        //    }
        //}

        [Test]
        public void TestKeyTrans()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.DesEde3Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();


            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.DesEde3Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.Id);
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void OriginatorInfoGeneration()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.OriginatorInformation = new OriginatorInformation(new OriginatorInfoGenerator(OrigCert).Generate());

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.DesEde3Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.DesEde3Cbc);

            var originatorCerts = new List<X509Certificate>(
                ed.OriginatorInformation.GetCertificates().EnumerateMatches(null));
            Assert.True(originatorCerts.Contains(OrigCert));

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.Id);
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransRC2bit40()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaBouncyCastle");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.RC2Cbc,
                keySize: 40);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.RC2Cbc);

            RC2CbcParameter rc2P = RC2CbcParameter.GetInstance(ed.EncryptionAlgorithmID.Parameters);
            Assert.AreEqual(160, rc2P.RC2ParameterVersionData.IntValueExact);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, bool.TrueString,
                    () => recipient.GetContent(ReciKP.Private));

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransRC4()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaBouncyCastle");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                PkcsObjectIdentifiers.rc4.GetID());

            RecipientInformationStore  recipients = ed.GetRecipientInfos();

            Assert.AreEqual(PkcsObjectIdentifiers.rc4, ed.EncryptionAlgorithmID.Algorithm);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, bool.TrueString,
                    () => recipient.GetContent(ReciKP.Private));

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTrans128RC4()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaBouncyCastle");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(ReciCert,
                new Asn1KeyWrapper("RSA/ECB/PKCS1Padding", ReciCert)));

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                PkcsObjectIdentifiers.rc4.GetID(), 128);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(PkcsObjectIdentifiers.rc4, ed.EncryptionAlgorithmID.Algorithm);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, bool.TrueString,
                    () => recipient.GetContent(ReciKP.Private));

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransOdes()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaBouncyCastle");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                OiwObjectIdentifiers.DesCbc.Id);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(OiwObjectIdentifiers.DesCbc, ed.EncryptionAlgorithmID.Algorithm);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransSmallAes()
        {
            byte[] data = new byte[] { 0, 1, 2, 3 };

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid,
                CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);
                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransSmallAesUsingOaep()
        {
            byte[] data = new byte[] { 0, 1, 2, 3 };

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(ReciCert,
                new Asn1KeyWrapper("RSA/None/OAEPwithSHA256andMGF1withSHA1Padding", ReciCert)));

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid,
                CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);
                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransSmallAesUsingOaepMixed()
        {
            byte[] data = new byte[] { 0, 1, 2, 3 };

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(ReciCert, new Asn1KeyWrapper("RSA/None/OAEPwithSHA256andMGF1withSHA1Padding", ReciCert)));

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid,
                CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);
                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransSmallAesUsingOaepMixedParams()
        {
            byte[] data = new byte[]{ 0, 1, 2, 3 };

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddRecipientInfoGenerator(
                new KeyTransRecipientInfoGenerator(
                    ReciCert,
                    new Asn1KeyWrapper(
                        PkcsObjectIdentifiers.IdRsaesOaep,
                        new RsaesOaepParameters(
                            new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance),
                            new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1,
                                new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance))),
                        ReciCert)));

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);
                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransSmallAesUsingPkcs1()
        {
            byte[] data = new byte[] { 0, 1, 2, 3 };

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddRecipientInfoGenerator(
                new KeyTransRecipientInfoGenerator(
                    ReciCert,
                    new Asn1KeyWrapper(
                        PkcsObjectIdentifiers.RsaEncryption, ReciCert)));

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid,
                CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);
                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestKeyTransCast5()
        {
            Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, bool.TrueString, () =>
            {
                TryKeyTrans(CmsEnvelopedGenerator.Cast5Cbc, new DerObjectIdentifier(CmsEnvelopedGenerator.Cast5Cbc),
                    typeof(Asn1Sequence));
            });
        }

        [Test]
        public void TestKeyTransAes128()
        {
            TryKeyTrans(CmsEnvelopedGenerator.Aes128Cbc,
                NistObjectIdentifiers.IdAes128Cbc,
                typeof(DerOctetString));
        }

        [Test]
        public void TestKeyTransAes192()
        {
            TryKeyTrans(CmsEnvelopedGenerator.Aes192Cbc,
                NistObjectIdentifiers.IdAes192Cbc,
                typeof(DerOctetString));
        }

        [Test]
        public void TestKeyTransAes256()
        {
            TryKeyTrans(CmsEnvelopedGenerator.Aes256Cbc,
                NistObjectIdentifiers.IdAes256Cbc,
                typeof(DerOctetString));
        }

        [Test]
        public void TestKeyTransSeed()
        {
            TryKeyTrans(CmsEnvelopedGenerator.SeedCbc,
                KisaObjectIdentifiers.IdSeedCbc,
                typeof(DerOctetString));
        }

        public void TestKeyTransCamellia128()
        {
            TryKeyTrans(CmsEnvelopedGenerator.Camellia128Cbc,
                NttObjectIdentifiers.IdCamellia128Cbc,
                typeof(DerOctetString));
        }

        public void TestKeyTransCamellia192()
        {
            TryKeyTrans(CmsEnvelopedGenerator.Camellia192Cbc,
                NttObjectIdentifiers.IdCamellia192Cbc,
                typeof(DerOctetString));
        }

        public void TestKeyTransCamellia256()
        {
            TryKeyTrans(CmsEnvelopedGenerator.Camellia256Cbc,
                NttObjectIdentifiers.IdCamellia256Cbc,
                typeof(DerOctetString));
        }

        private void TryKeyTrans(
            string              generatorOID,
            DerObjectIdentifier checkOID,
            Type                asn1Params)
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(ReciCert);

            CmsEnvelopedData ed = edGen.Generate(new CmsProcessableByteArray(data), generatorOID);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(checkOID, ed.EncryptionAlgorithmID.Algorithm);

            if (asn1Params != null)
            {
                Assert.IsTrue(asn1Params.IsInstanceOfType(ed.EncryptionAlgorithmID.Parameters.ToAsn1Object()));
            }

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.Id);
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestErroneousKek()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");
            KeyParameter kek = ParameterUtilities.CreateKeyParameter(
                "AES",
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });

            CmsEnvelopedData ed = new CmsEnvelopedData(oldKEK);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.DesEde3Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(recipient.KeyEncryptionAlgOid, NistObjectIdentifiers.IdAes128Wrap.Id);

                byte[] recData = recipient.GetContent(kek);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestDesKek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeDesEde192Key(), new DerObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
        }

        [Test]
        public void TestRC2128Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeRC2_128Key(), new DerObjectIdentifier("1.2.840.113549.1.9.16.3.7"));
        }

        [Test]
        public void TestAes128Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeAes128Key(), NistObjectIdentifiers.IdAes128Wrap);
        }

        [Test]
        public void TestAes192Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeAes192Key(), NistObjectIdentifiers.IdAes192Wrap);
        }

        [Test]
        public void TestAes256Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeAes256Key(), NistObjectIdentifiers.IdAes256Wrap);
        }

        [Test]
        public void TestSeed128Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeSeedKey(), KisaObjectIdentifiers.IdNpkiAppCmsSeedWrap);
        }

        [Test]
        public void TestCamellia128Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeCamellia128Key(), NttObjectIdentifiers.IdCamellia128Wrap);
        }

        [Test]
        public void TestCamellia192Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeCamellia192Key(), NttObjectIdentifiers.IdCamellia192Wrap);
        }

        [Test]
        public void TestCamellia256Kek()
        {
            TryKekAlgorithm(CmsTestUtil.MakeCamellia256Key(), NttObjectIdentifiers.IdCamellia256Wrap);
        }

        private void TryKekAlgorithm(KeyParameter kek, DerObjectIdentifier algOid)
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");
            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            byte[] kekId = new byte[] { 1, 2, 3, 4, 5 };

            string keyAlgorithm = ParameterUtilities.GetCanonicalAlgorithmName(algOid.Id);

            edGen.AddKekRecipient(keyAlgorithm, kek, kekId);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.DesEde3Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.DesEde3Cbc);

            var c = recipients.GetRecipients();

            Assert.IsTrue(c.Count > 0);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(algOid.Id, recipient.KeyEncryptionAlgOid);
                Assert.True(Arrays.AreEqual(recipient.RecipientID.KeyIdentifier, kekId));

                byte[] recData = recipient.GetContent(kek);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestECKeyAgree()
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyAgreementRecipient(
                CmsEnvelopedDataGenerator.ECDHSha1Kdf,
                OrigECKP.Private,
                OrigECKP.Public,
                ReciECCert,
                CmsEnvelopedGenerator.Aes128Wrap);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            ConfirmDataReceived(recipients, data, ReciECCert, ReciECKP.Private);
            ConfirmNumberRecipients(recipients, 1);
        }

        [Test]
        public void TestECMqvKeyAgree()
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyAgreementRecipient(
                CmsEnvelopedDataGenerator.ECMqvSha1Kdf,
                OrigECKP.Private,
                OrigECKP.Public,
                ReciECCert,
                CmsEnvelopedGenerator.Aes128Wrap);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            ConfirmDataReceived(recipients, data, ReciECCert, ReciECKP.Private);
            ConfirmNumberRecipients(recipients, 1);
        }

        [Test]
        public void TestECMqvKeyAgreeMultiple()
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            var recipientCerts = new List<X509Certificate>();
            recipientCerts.Add(ReciECCert);
            recipientCerts.Add(ReciECCert2);

            edGen.AddKeyAgreementRecipients(
                CmsEnvelopedGenerator.ECMqvSha1Kdf,
                OrigECKP.Private,
                OrigECKP.Public,
                recipientCerts,
                CmsEnvelopedGenerator.Aes128Wrap);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            ConfirmDataReceived(recipients, data, ReciECCert, ReciECKP.Private);
            ConfirmDataReceived(recipients, data, ReciECCert2, ReciECKP2.Private);
            ConfirmNumberRecipients(recipients, 2);
        }

        private static void ConfirmDataReceived(RecipientInformationStore recipients,
            byte[] expectedData, X509Certificate reciCert, AsymmetricKeyParameter reciPrivKey)
        {
            RecipientID rid = new RecipientID();
            rid.Issuer = reciCert.IssuerDN;
            rid.SerialNumber = reciCert.SerialNumber;

            RecipientInformation recipient = recipients[rid];
            Assert.IsNotNull(recipient);

            byte[] actualData = recipient.GetContent(reciPrivKey);
            Assert.IsTrue(Arrays.AreEqual(expectedData, actualData));
        }

        private static void ConfirmNumberRecipients(RecipientInformationStore recipients, int count)
        {
            Assert.AreEqual(count, recipients.GetRecipients().Count);
        }

        [Test]
        public void TestECKeyAgreeVectors()
        {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(ecKeyAgreeKey);

            VerifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.42", ecKeyAgreeMsgAES256);
            VerifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecKeyAgreeMsgAES128);
            VerifyECKeyAgreeVectors(privKey, "1.2.840.113549.3.7", ecKeyAgreeMsgDESEDE);
        }

        [Test]
        public void TestECMqvKeyAgreeVectors()
        {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(ecKeyAgreeKey);

            VerifyECMqvKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecMqvKeyAgreeMsgAes128);
        }

        [Test]
        public void TestECKeyAgreeVectorsOpenSsl()
        {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(openSslEcKeyAgreeKey);

            string ecdhSha1Kdf = CmsEnvelopedGenerator.ECDHSha1Kdf;
            string ecdhSha256Kdf = CmsEnvelopedGenerator.ECDHSha256Kdf;

            VerifyECKeyAgreeVectors(privKey, ecdhSha1Kdf, CmsEnvelopedGenerator.Aes128Cbc,
                openSslEcKeyAgreeMsgAes128Sha1);
            VerifyECKeyAgreeVectors(privKey, ecdhSha1Kdf, CmsEnvelopedGenerator.Aes256Cbc,
                openSslEcKeyAgreeMsgAes256Sha1);
            VerifyECKeyAgreeVectors(privKey, ecdhSha256Kdf, CmsEnvelopedGenerator.Aes256Cbc,
                openSslEcKeyAgreeMsgAes256Sha256);
            VerifyECKeyAgreeVectors(privKey, ecdhSha1Kdf, CmsEnvelopedGenerator.DesEde3Cbc,
                openSslEcKeyAgreeMsgDesEde3Sha1);
        }

        [Test]
        public void TestECKeyAgreeVectorsLegacyKdf()
        {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(openSslEcKeyAgreeKey);

            string ecdhSha1Kdf = CmsEnvelopedGenerator.ECDHSha1Kdf;
            string ecdhSha256Kdf = CmsEnvelopedGenerator.ECDHSha256Kdf;

            // Default: the legacy derivation is retried, so pre-2.8.0 messages remain readable
            VerifyECKeyAgreeVectors(privKey, ecdhSha1Kdf, CmsEnvelopedGenerator.Aes128Cbc,
                legacyEcKeyAgreeMsgAes128Sha1);
            VerifyECKeyAgreeVectors(privKey, ecdhSha256Kdf, CmsEnvelopedGenerator.Aes256Cbc,
                legacyEcKeyAgreeMsgAes256Sha256);

            Properties.WithThreadProperty(Properties.CmsAllowLegacyKeyAgreeKdf, bool.FalseString, () =>
            {
                // Standard-only: the legacy messages must fail ...
                Assert.Throws<CmsException>(() => VerifyECKeyAgreeVectors(privKey, ecdhSha1Kdf,
                    CmsEnvelopedGenerator.Aes128Cbc, legacyEcKeyAgreeMsgAes128Sha1));
                Assert.Throws<CmsException>(() => VerifyECKeyAgreeVectors(privKey, ecdhSha256Kdf,
                    CmsEnvelopedGenerator.Aes256Cbc, legacyEcKeyAgreeMsgAes256Sha256));

                // ... while standard messages (absent parameters) and explicit-NULL messages are unaffected
                VerifyECKeyAgreeVectors(privKey, ecdhSha1Kdf, CmsEnvelopedGenerator.Aes128Cbc,
                    openSslEcKeyAgreeMsgAes128Sha1);
                VerifyECKeyAgreeVectors(PrivateKeyFactory.CreateKey(ecKeyAgreeKey), "2.16.840.1.101.3.4.1.2",
                    ecKeyAgreeMsgAES128);
                VerifyECMqvKeyAgreeVectors(PrivateKeyFactory.CreateKey(ecKeyAgreeKey), "2.16.840.1.101.3.4.1.2",
                    ecMqvKeyAgreeMsgAes128);
            });
        }

        private static IEnumerable<TestCaseData> ECMqvKeyAgreeLegacyKdfVectors()
        {
            yield return new TestCaseData(CmsEnvelopedGenerator.ECMqvSha1Kdf, "EnvelopedData_ECMQV-SHA1KDF_AES128.pem")
                .SetArgDisplayNames("ECMQV-SHA1-AES128");
            yield return new TestCaseData(CmsEnvelopedGenerator.ECMqvSha1Kdf,
                "EnvelopedData_ECMQV-SHA1KDF_AES128_no-addedukm.pem")
                .SetArgDisplayNames("ECMQV-SHA1-AES128-no-ukm");
            yield return new TestCaseData(CmsEnvelopedGenerator.ECMqvSha256Kdf,
                "EnvelopedData_ECMQV-SHA256KDF_AES128.pem")
                .SetArgDisplayNames("ECMQV-SHA256-AES128");
            yield return new TestCaseData(CmsEnvelopedGenerator.ECMqvSha256Kdf,
                "EnvelopedData_ECMQV-SHA256KDF_AES128_no-addedukm.pem")
                .SetArgDisplayNames("ECMQV-SHA256-AES128-no-ukm");
        }

        /*
         * After bc-java's testECMQVKeyAgreeLegacyVectors: ECMQV messages whose KEK was derived from the raw addedukm
         * are read through the legacy retry, which CmsAllowLegacyKeyAgreeKdf (default on) controls.
         */
        [TestCaseSource(nameof(ECMqvKeyAgreeLegacyKdfVectors))]
        public void TestECMqvKeyAgreeLegacyKdfVectors(string agreeAlg, string fileName)
        {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(
                LoadPemContents(MqvLegacyKdfVectorsPath, "recipient_p384.pem"));
            byte[] message = LoadPemContents(MqvLegacyKdfVectorsPath, fileName);

            VerifyECMqvKeyAgreeVectors(privKey, agreeAlg, CmsEnvelopedGenerator.Aes128Cbc, message);

            Properties.WithThreadProperty(Properties.CmsAllowLegacyKeyAgreeKdf, bool.FalseString, () =>
            {
                Assert.Throws<CmsException>(() => VerifyECMqvKeyAgreeVectors(privKey, agreeAlg,
                    CmsEnvelopedGenerator.Aes128Cbc, message));
            });
        }

        [Test]
        public void TestECKeyAgreeWrapAlgorithmParameters()
        {
            // RFC 5753 section 7.2: AES key wrap has absent parameters; RFC 3370 section 4.3.1: 3DES wrap has NULL.
            string ecdhSha1Kdf = CmsEnvelopedGenerator.ECDHSha1Kdf;
            string ecMqvSha1Kdf = CmsEnvelopedGenerator.ECMqvSha1Kdf;

            CheckECKeyAgreeWrapAlgorithmParameters(ecdhSha1Kdf, CmsEnvelopedGenerator.Aes128Wrap, expectNull: false);
            CheckECKeyAgreeWrapAlgorithmParameters(ecdhSha1Kdf, CmsEnvelopedGenerator.Aes256Wrap, expectNull: false);
            CheckECKeyAgreeWrapAlgorithmParameters(ecdhSha1Kdf, CmsEnvelopedGenerator.DesEde3Wrap, expectNull: true);

            CheckECKeyAgreeWrapAlgorithmParameters(ecMqvSha1Kdf, CmsEnvelopedGenerator.Aes128Wrap, expectNull: false);
            CheckECKeyAgreeWrapAlgorithmParameters(ecMqvSha1Kdf, CmsEnvelopedGenerator.Aes256Wrap, expectNull: false);
            CheckECKeyAgreeWrapAlgorithmParameters(ecMqvSha1Kdf, CmsEnvelopedGenerator.DesEde3Wrap, expectNull: true);
        }

        private static void CheckECKeyAgreeWrapAlgorithmParameters(string agreeAlg, string wrapAlg, bool expectNull)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();
            edGen.AddKeyAgreementRecipient(agreeAlg, OrigECKP.Private, OrigECKP.Public, ReciECCert, wrapAlg);

            CmsEnvelopedData ed = edGen.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes128Cbc);

            // Re-parse from the encoding so we check what is actually transmitted
            ed = new CmsEnvelopedData(ed.GetEncoded());

            Asn1Set recipientInfos = ed.EnvelopedData.RecipientInfos;
            Assert.AreEqual(1, recipientInfos.Count);

            var keyAgreeRecipientInfo = (Asn1.Cms.KeyAgreeRecipientInfo)Asn1.Cms.RecipientInfo.GetInstance(
                recipientInfos[0]).Info;
            AlgorithmIdentifier wrapAlgID = AlgorithmIdentifier.GetInstance(
                keyAgreeRecipientInfo.KeyEncryptionAlgorithm.Parameters);

            Assert.AreEqual(agreeAlg, keyAgreeRecipientInfo.KeyEncryptionAlgorithm.Algorithm.GetID());
            Assert.AreEqual(wrapAlg, wrapAlgID.Algorithm.GetID());
            if (expectNull)
            {
                Assert.AreEqual(DerNull.Instance, wrapAlgID.Parameters);
            }
            else
            {
                Assert.IsNull(wrapAlgID.Parameters);
            }

            ConfirmDataReceived(ed.GetRecipientInfos(), data, ReciECCert, ReciECKP.Private);
        }

        /*
         * RFC 5753 sec. 7.2: the ukm (ECDH), or the addedukm of the MQVuserKeyingMaterial (1-Pass ECMQV), is the
         * entityUInfo of the ECC-CMS-SharedInfo fed to the KDF.
         */
        public enum KeyAgreeScheme { ECDH, ECCDH, ECMqv }

        private static IEnumerable<TestCaseData> ECKeyAgreeUkmVectors()
        {
            yield return new TestCaseData(KeyAgreeScheme.ECDH, CmsEnvelopedGenerator.ECDHSha1Kdf, "SHA-1",
                CmsEnvelopedGenerator.Aes128Cbc, "EnvelopedData_ECDH-SHA1KDF_AES128.pem", true)
                .SetArgDisplayNames("ECDH-SHA1-AES128");
            yield return new TestCaseData(KeyAgreeScheme.ECDH, CmsEnvelopedGenerator.ECDHSha256Kdf, "SHA-256",
                CmsEnvelopedGenerator.Aes256Cbc, "EnvelopedData_ECDH-SHA256KDF_AES256.pem", true)
                .SetArgDisplayNames("ECDH-SHA256-AES256");
            yield return new TestCaseData(KeyAgreeScheme.ECCDH, CmsEnvelopedGenerator.ECCDHSha256Kdf, "SHA-256",
                CmsEnvelopedGenerator.Aes128Cbc, "EnvelopedData_ECCDH-SHA256KDF_AES128.pem", true)
                .SetArgDisplayNames("ECCDH-SHA256-AES128");
            yield return new TestCaseData(KeyAgreeScheme.ECDH, CmsEnvelopedGenerator.ECDHSha1Kdf, "SHA-1",
                CmsEnvelopedGenerator.DesEde3Cbc, "EnvelopedData_ECDH-SHA1KDF_DESEDE3.pem", true)
                .SetArgDisplayNames("ECDH-SHA1-DESEDE3");
            yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha1Kdf, "SHA-1",
                CmsEnvelopedGenerator.Aes128Cbc, "EnvelopedData_ECMQV-SHA1KDF_AES128.pem", true)
                .SetArgDisplayNames("ECMQV-SHA1-AES128");
            yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha1Kdf, "SHA-1",
                CmsEnvelopedGenerator.Aes128Cbc, "EnvelopedData_ECMQV-SHA1KDF_AES128_no-addedukm.pem", false)
                .SetArgDisplayNames("ECMQV-SHA1-AES128-no-ukm");
            yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha1Kdf, "SHA-1",
                CmsEnvelopedGenerator.DesEde3Cbc, "EnvelopedData_ECMQV-SHA1KDF_DESEDE3.pem", true)
                .SetArgDisplayNames("ECMQV-SHA1-DESEDE3");
            yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha256Kdf, "SHA-256",
                CmsEnvelopedGenerator.Aes256Cbc, "EnvelopedData_ECMQV-SHA256KDF_AES256.pem", true)
                .SetArgDisplayNames("ECMQV-SHA256-AES256");
            yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha256Kdf, "SHA-256",
                CmsEnvelopedGenerator.Aes256Cbc, "EnvelopedData_ECMQV-SHA256KDF_AES256_no-addedukm.pem", false)
                .SetArgDisplayNames("ECMQV-SHA256-AES256-no-ukm");
        }

        private static IEnumerable<TestCaseData> KeyAgreeUkmSchemes()
        {
            foreach (bool withUkm in new[] { true, false })
            {
                string suffix = withUkm ? "" : "-no-ukm";

                yield return new TestCaseData(KeyAgreeScheme.ECDH, CmsEnvelopedGenerator.ECDHSha1Kdf, "SHA-1",
                    withUkm).SetArgDisplayNames("ECDH-SHA1" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECDH, CmsEnvelopedGenerator.ECDHSha256Kdf, "SHA-256",
                    withUkm).SetArgDisplayNames("ECDH-SHA256" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECCDH, CmsEnvelopedGenerator.ECCDHSha256Kdf, "SHA-256",
                    withUkm).SetArgDisplayNames("ECCDH-SHA256" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha1Kdf, "SHA-1",
                    withUkm).SetArgDisplayNames("ECMQV-SHA1" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha224Kdf, "SHA-224",
                    withUkm).SetArgDisplayNames("ECMQV-SHA224" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha256Kdf, "SHA-256",
                    withUkm).SetArgDisplayNames("ECMQV-SHA256" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha384Kdf, "SHA-384",
                    withUkm).SetArgDisplayNames("ECMQV-SHA384" + suffix);
                yield return new TestCaseData(KeyAgreeScheme.ECMqv, CmsEnvelopedGenerator.ECMqvSha512Kdf, "SHA-512",
                    withUkm).SetArgDisplayNames("ECMQV-SHA512" + suffix);
            }
        }

        [TestCaseSource(nameof(ECKeyAgreeUkmVectors))]
        public void TestECKeyAgreeUkmVectors(KeyAgreeScheme scheme, string agreeAlg, string kdfDigest,
            string contentAlg, string fileName, bool withUkm)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            string path = scheme == KeyAgreeScheme.ECMqv ? MqvUkmVectorsPath : EcdhUkmVectorsPath;

            var reciPriv = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                LoadPemContents(path, "recipient_p256.pem"));

            CmsEnvelopedData ed = new CmsEnvelopedData(LoadPemContents(path, fileName));
            Assert.That(ed.EncryptionAlgOid, Is.EqualTo(contentAlg));

            var recipients = ed.GetRecipientInfos().GetRecipients();
            Assert.That(recipients.Count, Is.EqualTo(1));

            foreach (RecipientInformation recipient in recipients)
            {
                Assert.That(recipient.KeyEncryptionAlgOid, Is.EqualTo(agreeAlg));
                Assert.That(recipient.GetContent(reciPriv), Is.EqualTo(data));
            }

            CheckKeyAgreeUkmKek(ed, 0, reciPriv, scheme, kdfDigest, withUkm ? keyAgreeUkm : null);
        }

        /*
         * After bc-java's doRFC8418Round/checkRFC8418Kek and doECMQVKekRound/checkECMQVKek: a round trip against
         * ourselves cannot tell whether the ukm reached the KDF, or in which form, so the KEK is also derived
         * independently of the CMS code. Two recipients share the KeyAgreeRecipientInfo, so the sender's agreement
         * parameters are used more than once.
         */
        [TestCaseSource(nameof(KeyAgreeUkmSchemes))]
        public void TestKeyAgreeUkmRoundTrip(KeyAgreeScheme scheme, string agreeAlg, string kdfDigest, bool withUkm)
        {
            byte[] ukm = withUkm ? keyAgreeUkm : null;

            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();
            edGen.AddRecipientInfoGenerator(new KeyAgreeRecipientInfoGenerator(new[] { ReciECCert, ReciECCert2 })
            {
                KeyAgreementOid = new DerObjectIdentifier(agreeAlg),
                KeyEncryptionOid = new DerObjectIdentifier(CmsEnvelopedGenerator.Aes128Wrap),
                SenderKeyPair = OrigECKP,
                UserKeyingMaterial = ukm,
            });

            CmsEnvelopedData ed = edGen.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes128Cbc);

            // Re-parse from the encoding so we check what is actually transmitted
            ed = new CmsEnvelopedData(ed.GetEncoded());

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            ConfirmDataReceived(recipients, data, ReciECCert, ReciECKP.Private);
            ConfirmDataReceived(recipients, data, ReciECCert2, ReciECKP2.Private);
            ConfirmNumberRecipients(recipients, 2);

            CheckKeyAgreeUkmKek(ed, 0, (ECPrivateKeyParameters)ReciECKP.Private, scheme, kdfDigest, ukm);
            CheckKeyAgreeUkmKek(ed, 1, (ECPrivateKeyParameters)ReciECKP2.Private, scheme, kdfDigest, ukm);
        }

        [Test]
        public void TestECMqvKeyAgreeWithoutUkm()
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();
            edGen.AddKeyAgreementRecipient(CmsEnvelopedGenerator.ECMqvSha1Kdf, OrigECKP.Private, OrigECKP.Public,
                ReciECCert, CmsEnvelopedGenerator.Aes128Wrap);

            CmsEnvelopedData ed = edGen.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes128Cbc);

            // Rebuild the message with the (mandatory) ukm removed from the KeyAgreeRecipientInfo
            var kari = GetKeyAgreeRecipientInfo(ed);
            Assert.That(kari.UserKeyingMaterial, Is.Not.Null);

            var strippedKari = new Asn1.Cms.KeyAgreeRecipientInfo(kari.Originator, null, kari.KeyEncryptionAlgorithm,
                kari.RecipientEncryptedKeys);
            var stripped = WithKeyAgreeRecipientInfo(ed, strippedKari);

            RecipientInformation recipient = stripped.GetRecipientInfos().GetRecipients()[0];

            var e = Assert.Throws<CmsException>(() => recipient.GetContent(ReciECKP.Private));
            Assert.That(e.Message, Is.EqualTo("User keying material must be present for MQV."));
            Assert.That(e.InnerException, Is.Null);
        }

        private static IEnumerable<TestCaseData> ECDHKeyAgreeRawUkmSchemes()
        {
            yield return new TestCaseData(KeyAgreeScheme.ECDH, CmsEnvelopedGenerator.ECDHSha1Kdf, "SHA-1")
                .SetArgDisplayNames("ECDH-SHA1");
            yield return new TestCaseData(KeyAgreeScheme.ECCDH, CmsEnvelopedGenerator.ECCDHSha256Kdf, "SHA-256")
                .SetArgDisplayNames("ECCDH-SHA256");
        }

        /*
         * Some senders give the KDF the raw ukm as its SharedInfo, which the legacy retry accepts (as bc-java's
         * JceKeyAgreeRecipient does) unless CmsAllowLegacyKeyAgreeKdf is off. No ECDH sample of that form exists, so
         * one is made by re-wrapping the content-encryption key of a conformant message under the raw-form KEK.
         */
        [TestCaseSource(nameof(ECDHKeyAgreeRawUkmSchemes))]
        public void TestECDHKeyAgreeLegacyRawUkm(KeyAgreeScheme scheme, string agreeAlg, string kdfDigest)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();
            edGen.AddRecipientInfoGenerator(new KeyAgreeRecipientInfoGenerator(new[] { ReciECCert })
            {
                KeyAgreementOid = new DerObjectIdentifier(agreeAlg),
                KeyEncryptionOid = new DerObjectIdentifier(CmsEnvelopedGenerator.Aes128Wrap),
                SenderKeyPair = OrigECKP,
                UserKeyingMaterial = keyAgreeUkm,
            });

            CmsEnvelopedData ed = edGen.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes128Cbc);

            var kari = GetKeyAgreeRecipientInfo(ed);
            var wrapAlgID = AlgorithmIdentifier.GetInstance(kari.KeyEncryptionAlgorithm.Parameters);
            var recipientEncryptedKey = Asn1.Cms.RecipientEncryptedKey.GetInstance(kari.RecipientEncryptedKeys[0]);
            byte[] encryptedKey = recipientEncryptedKey.EncryptedKey.GetOctets();

            byte[] z = CalculateKeyAgreeZ(kari, (ECPrivateKeyParameters)ReciECKP.Private, scheme);
            int kekLength = GeneratorUtilities.GetDefaultKeySize(wrapAlgID.Algorithm) / 8;

            IWrapper unwrapper = WrapperUtilities.GetWrapper(wrapAlgID.Algorithm);
            unwrapper.Init(false, ParameterUtilities.CreateKeyParameter(wrapAlgID.Algorithm,
                DeriveKeyAgreeKek(kdfDigest, z, wrapAlgID, keyAgreeUkm)));
            byte[] cek = unwrapper.Unwrap(encryptedKey, 0, encryptedKey.Length);

            IWrapper wrapper = WrapperUtilities.GetWrapper(wrapAlgID.Algorithm);
            wrapper.Init(true, ParameterUtilities.CreateKeyParameter(wrapAlgID.Algorithm,
                DeriveX963Kek(kdfDigest, z, keyAgreeUkm, kekLength)));
            byte[] rawEncryptedKey = wrapper.Wrap(cek, 0, cek.Length);

            var rawKari = new Asn1.Cms.KeyAgreeRecipientInfo(kari.Originator, kari.UserKeyingMaterial,
                kari.KeyEncryptionAlgorithm, new DerSequence(new Asn1.Cms.RecipientEncryptedKey(
                    recipientEncryptedKey.Identifier, new DerOctetString(rawEncryptedKey))));
            byte[] message = WithKeyAgreeRecipientInfo(ed, rawKari).GetEncoded();

            VerifyECKeyAgreeVectors(ReciECKP.Private, agreeAlg, CmsEnvelopedGenerator.Aes128Cbc, message);

            Properties.WithThreadProperty(Properties.CmsAllowLegacyKeyAgreeKdf, bool.FalseString, () =>
            {
                Assert.Throws<CmsException>(() => VerifyECKeyAgreeVectors(ReciECKP.Private, agreeAlg,
                    CmsEnvelopedGenerator.Aes128Cbc, message));
            });
        }

        private static CmsEnvelopedData WithKeyAgreeRecipientInfo(CmsEnvelopedData ed,
            Asn1.Cms.KeyAgreeRecipientInfo kari)
        {
            var envelopedData = ed.EnvelopedData;
            var newEnvelopedData = new Asn1.Cms.EnvelopedData(envelopedData.OriginatorInfo,
                new DerSet(new Asn1.Cms.RecipientInfo(kari)), envelopedData.EncryptedContentInfo,
                envelopedData.UnprotectedAttrs);
            return new CmsEnvelopedData(new Asn1.Cms.ContentInfo(ed.ContentInfo.ContentType, newEnvelopedData));
        }

        /// <summary>
        /// Derive the KEK for one recipient independently of the CMS code (RFC 5753 sec. 7.2) and check that it
        /// unwraps that recipient's encryptedKey, while the raw form (the ukm itself, or nothing, as the KDF's
        /// SharedInfo) and, given a ukm, the same derivation without the entityUInfo do not.
        /// </summary>
        private static void CheckKeyAgreeUkmKek(CmsEnvelopedData ed, int recipientIndex,
            ECPrivateKeyParameters reciPriv, KeyAgreeScheme scheme, string kdfDigest, byte[] ukm)
        {
            var kari = GetKeyAgreeRecipientInfo(ed);
            var wrapAlgID = AlgorithmIdentifier.GetInstance(kari.KeyEncryptionAlgorithm.Parameters);
            byte[] encryptedKey = Asn1.Cms.RecipientEncryptedKey.GetInstance(
                kari.RecipientEncryptedKeys[recipientIndex]).EncryptedKey.GetOctets();

            byte[] entityUInfo;
            if (scheme == KeyAgreeScheme.ECMqv)
            {
                // RFC 5753 sec. 3.2.1: the ukm MUST be present, since it carries the ephemeral public key
                Assert.That(kari.UserKeyingMaterial, Is.Not.Null, "MQVuserKeyingMaterial not carried in the message");

                var mqvUkm = Asn1.Cms.Ecc.MQVuserKeyingMaterial.GetInstance(kari.UserKeyingMaterial.GetOctets());
                entityUInfo = mqvUkm.AddedUkm?.GetOctets();
            }
            else
            {
                entityUInfo = kari.UserKeyingMaterial?.GetOctets();
            }

            Assert.That(entityUInfo, Is.EqualTo(ukm), "ukm not carried as expected in the message");

            byte[] z = CalculateKeyAgreeZ(kari, reciPriv, scheme);

            Assert.That(UnwrapsWith(DeriveKeyAgreeKek(kdfDigest, z, wrapAlgID, ukm), wrapAlgID, encryptedKey),
                Is.True, "the KEK derived from ECC-CMS-SharedInfo does not open the message");
            if (ukm != null)
            {
                Assert.That(UnwrapsWith(DeriveKeyAgreeKek(kdfDigest, z, wrapAlgID, null), wrapAlgID, encryptedKey),
                    Is.False, "the KEK derived without entityUInfo still opens the message");
            }

            int kekLength = GeneratorUtilities.GetDefaultKeySize(wrapAlgID.Algorithm) / 8;
            Assert.That(UnwrapsWith(DeriveX963Kek(kdfDigest, z, ukm, kekLength), wrapAlgID, encryptedKey),
                Is.False, "the KEK derived from the raw ukm still opens the message");
        }

        /// <summary>Z, the recipient's shared secret, calculated independently of the CMS code.</summary>
        private static byte[] CalculateKeyAgreeZ(Asn1.Cms.KeyAgreeRecipientInfo kari, ECPrivateKeyParameters reciPriv,
            KeyAgreeScheme scheme)
        {
            var originatorKey = DecodeOriginatorPublicKey(reciPriv, kari.Originator.OriginatorKey);

            IBasicAgreement agreement;
            ICipherParameters publicParams;

            if (scheme == KeyAgreeScheme.ECMqv)
            {
                var mqvUkm = Asn1.Cms.Ecc.MQVuserKeyingMaterial.GetInstance(kari.UserKeyingMaterial.GetOctets());
                var ephemeralKey = DecodeOriginatorPublicKey(reciPriv, mqvUkm.EphemeralPublicKey);

                // 1-Pass ECMQV: the recipient's static key is used in both roles
                agreement = new ECMqvBasicAgreement();
                agreement.Init(new MqvPrivateParameters(reciPriv, reciPriv));
                publicParams = new MqvPublicParameters(originatorKey, ephemeralKey);
            }
            else
            {
                if (scheme == KeyAgreeScheme.ECCDH)
                {
                    agreement = new ECDHCBasicAgreement();
                }
                else
                {
                    agreement = new ECDHBasicAgreement();
                }
                agreement.Init(reciPriv);
                publicParams = originatorKey;
            }

            return BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(),
                agreement.CalculateAgreement(publicParams));
        }

        private static ECPublicKeyParameters DecodeOriginatorPublicKey(ECPrivateKeyParameters reciPriv,
            Asn1.Cms.OriginatorPublicKey originatorKey)
        {
            ECDomainParameters dp = reciPriv.Parameters;
            return new ECPublicKeyParameters(dp.Curve.DecodePoint(originatorKey.PublicKey.GetOctets()), dp);
        }

        private static byte[] DeriveKeyAgreeKek(string kdfDigest, byte[] z, AlgorithmIdentifier wrapAlgID,
            byte[] entityUInfo)
        {
            int kekBits = GeneratorUtilities.GetDefaultKeySize(wrapAlgID.Algorithm);

            var sharedInfo = new Asn1.Cms.Ecc.ECC_CMS_SharedInfo(wrapAlgID,
                DerOctetString.WithContentsOptional(entityUInfo),
                DerOctetString.WithContents(Pack.UInt32_To_BE((uint)kekBits)));

            return DeriveX963Kek(kdfDigest, z, sharedInfo.GetEncoded(Asn1Encodable.Der), kekBits / 8);
        }

        // The X9.63 KDF of SEC 1 sec. 3.6.1
        private static byte[] DeriveX963Kek(string kdfDigest, byte[] z, byte[] sharedInfo, int kekLength)
        {
            var kdf = new Kdf2BytesGenerator(DigestUtilities.GetDigest(kdfDigest));
            kdf.Init(new KdfParameters(z, sharedInfo));

            byte[] kek = new byte[kekLength];
            kdf.GenerateBytes(kek, 0, kek.Length);
            return kek;
        }

        private static bool UnwrapsWith(byte[] kek, AlgorithmIdentifier wrapAlgID, byte[] encryptedKey)
        {
            IWrapper wrapper = WrapperUtilities.GetWrapper(wrapAlgID.Algorithm);
            wrapper.Init(false, ParameterUtilities.CreateKeyParameter(wrapAlgID.Algorithm, kek));

            try
            {
                wrapper.Unwrap(encryptedKey, 0, encryptedKey.Length);
                return true;
            }
            catch (InvalidCipherTextException)
            {
                return false;
            }
        }

        private static Asn1.Cms.KeyAgreeRecipientInfo GetKeyAgreeRecipientInfo(CmsEnvelopedData ed) =>
            (Asn1.Cms.KeyAgreeRecipientInfo)Asn1.Cms.RecipientInfo.GetInstance(ed.EnvelopedData.RecipientInfos[0]).Info;

        private static byte[] LoadPemContents(string path, string name)
        {
            using (var pemReader = new PemReader(new StreamReader(SimpleTest.FindTestResource(path, name))))
            {
                return pemReader.ReadPemObject().Content;
            }
        }

        [Test]
        public void TestPasswordAes256()
        {
            PasswordTest(CmsEnvelopedGenerator.Aes256Cbc);
            PasswordUtf8Test(CmsEnvelopedGenerator.Aes256Cbc);
        }

        [Test]
        public void TestPasswordDesEde()
        {
            PasswordTest(CmsEnvelopedGenerator.DesEde3Cbc);
            PasswordUtf8Test(CmsEnvelopedGenerator.DesEde3Cbc);
        }

        [Test]
        public void TestPasswordRecipientIterationCountBound()
        {
            // A PasswordRecipientInfo's keyDerivationAlgorithm is attacker-supplied and unauthenticated, so the
            // PBKDF2 iteration count must be bounded before the KEK is derived (CPU-DoS guard). Build a PBKDF2
            // algorithm identifier with a normal count, then lower the bound below it: key construction (the
            // chokepoint) must be rejected before any derivation runs.
            var kdfAlg = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbkdf2, new Pbkdf2Params(new byte[20], 2048));

            Properties.WithThreadProperty(Properties.PbeMaxIterationCount, "1", () =>
            {
                Assert.Throws<ArgumentException>(
                    () => new Pkcs5Scheme2PbeKey("password".ToCharArray(), kdfAlg));
                Assert.Throws<ArgumentException>(
                    () => new Pkcs5Scheme2Utf8PbeKey("password".ToCharArray(), kdfAlg));
            });
        }

        [Test]
        public void TestRfc4134Ex5_1()
        {
            byte[] data = Hex.Decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

            AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(bobPrivRsaEncrypt);

            CmsEnvelopedData ed = new CmsEnvelopedData(rfc4134ex5_1);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual("1.2.840.113549.3.7", ed.EncryptionAlgOid);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                byte[] recData = recipient.GetContent(key);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        [Test]
        public void TestRfc4134Ex5_2()
        {
            byte[] data = Hex.Decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

            AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(bobPrivRsaEncrypt);

            CmsEnvelopedData ed = new CmsEnvelopedData(rfc4134ex5_2);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual("1.2.840.113549.3.2", ed.EncryptionAlgOid);

            var c = recipients.GetRecipients();
            var e = c.GetEnumerator();

            if (!e.MoveNext())
            {
                Assert.Fail("no recipient found");
                return;
            }

            do
            {
                RecipientInformation recipient = e.Current;

                if (recipient is KeyTransRecipientInformation)
                {
                    byte[] recData = Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, bool.TrueString,
                        () => recipient.GetContent(key));

                    Assert.IsTrue(Arrays.AreEqual(data, recData));
                }
            }
            while (e.MoveNext());
        }

        [Test]
        public void OriginatorInfo()
        {
            CmsEnvelopedData env = new CmsEnvelopedData(CmsSampleMessages.originatorMessage);

            RecipientInformationStore recipients = env.GetRecipientInfos();

            var originatorCerts = new List<X509Certificate>(
                env.OriginatorInformation.GetCertificates().EnumerateMatches(null));

            var expectedSubject = new X509Name("C=US,O=U.S. Government,OU=HSPD12Lab,OU=Agents,CN=user1");
            Assert.That(expectedSubject.Equivalent(originatorCerts[0].SubjectDN));

            Assert.AreEqual(CmsEnvelopedGenerator.DesEde3Cbc, env.EncryptionAlgOid);
        }

        //[Test]
        //public void TestGost3410_2012_KeyAgree()
        //{
        //    AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(gost2012_Reci_Key);

        //    CmsEnvelopedData ed = new CmsEnvelopedData(gost2012_Reci_Msg);

        //    RecipientInformationStore recipients = ed.GetRecipientInfos();

        //    Assert.AreEqual(ed.EncryptionAlgOid, CryptoProObjectIdentifiers.GostR28147Gcfb.Id);

        //    var c = recipients.GetRecipients();

        //    Assert.AreEqual(1, c.Count);

        //    foreach (RecipientInformation recipient in c)
        //    {
        //        Assert.AreEqual(recipient.KeyEncryptionAlgOid,
        //            RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.Id);

        //        byte[] recData = recipient.GetContent(privKey);

        //        Assert.AreEqual("Hello World!", Strings.FromByteArray(recData));
        //    }

        //    var cert = new X509CertificateParser().ReadCertificate(gost2012_Reci_Cert);
        //    //CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        //    //RecipientId id = new JceKeyAgreeRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_Reci_Cert)));
        //    //         RecipientID id = new KeyAgreeRecipentID(cert);

        //    //var collection = recipients.GetRecipients(id);
        //    //if (collection.Count != 1)
        //    //{
        //    //    Assert.Fail("recipients not matched using general recipient ID.");
        //    //}
        //    //Assert.IsTrue(collection[0] is RecipientInformation);
        //}

        private const string BadPaddingMessage = "bad padding in message.";

        [Test]
        public void TestKeyTransRsaPkcs1PaddingOracleClosed()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();
            edGen.AddKeyTransRecipient(ReciCert_2048);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes256Cbc);

            // Sanity: the untampered message still decrypts to the original content.
            Assert.IsTrue(Arrays.AreEqual(data, DecryptFirst(ed, ReciKP_2048.Private)));

            // (a) A CEK ciphertext with invalid PKCS#1 v1.5 padding.
            CmsEnvelopedData badPadding = ReplaceKeyTransEncryptedKey(ed,
                MakeBadPaddingCiphertext(ReciCert_2048.GetPublicKey()));

            // (b) A CEK ciphertext with valid PKCS#1 v1.5 padding but the wrong key.
            var rsaEncrypt = new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(
                new Org.BouncyCastle.Crypto.Engines.RsaEngine());
            rsaEncrypt.Init(true, ReciCert_2048.GetPublicKey());
            byte[] wrongKey = new byte[32];
            byte[] wrongKeyCiphertext = rsaEncrypt.ProcessBlock(wrongKey, 0, wrongKey.Length);
            CmsEnvelopedData validPaddingWrongKey = ReplaceKeyTransEncryptedKey(ed, wrongKeyCiphertext);

            // The fix removes the unwrap-layer padding oracle: a bad-padding CEK must no longer be distinguishable
            // as "bad padding in message." (which used to separate it from a well-padded but wrong CEK). With a
            // known content-key size both tampered messages now fail identically, downstream at the content layer.
            Assert.AreNotEqual(BadPaddingMessage, TryDecryptExpectFailure(badPadding, ReciKP_2048.Private));
            Assert.AreNotEqual(BadPaddingMessage, TryDecryptExpectFailure(validPaddingWrongKey, ReciKP_2048.Private));
        }

        [Test]
        public void TestKeyTransRsaPkcs1UnknownContentKeySize()
        {
            byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();
            edGen.AddKeyTransRecipient(ReciCert_2048);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes256Cbc);

            // Rewrite the content-encryption algorithm to an OID with no registered key size, and give the CEK
            // invalid PKCS#1 v1.5 padding.
            CmsEnvelopedData tampered = ReplaceContentAlgAndEncryptedKey(
                ed, new DerObjectIdentifier("1.2.3.4.5.6.7.8"),
                MakeBadPaddingCiphertext(ReciCert_2048.GetPublicKey()));

            // Strict default: with no known content-key length there is nothing to bound the decoding with, so the
            // unwrap fails closed rather than falling back to the oracle-prone plain decoding.
            string strict = TryDecryptExpectFailure(tampered, ReciKP_2048.Private);
            Assert.AreNotEqual(BadPaddingMessage, strict);
            StringAssert.Contains("no fixed size", strict);

            // Opt in to the legacy behaviour: the plain unwrap is restored and a bad-padding CEK is once again
            // reported as "bad padding in message." (the historical, distinguishable failure).
            string lenient = Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, "true",
                () => TryDecryptExpectFailure(tampered, ReciKP_2048.Private));
            Assert.AreEqual(BadPaddingMessage, lenient);
        }

        // Raw RSA-encrypt a block that is not valid PKCS#1 v1.5 type-2 padding, producing a full modulus-length
        // ciphertext whose decryption deterministically fails the padding check (rather than a short input that
        // would trip the engine's block-size check before any padding logic runs).
        private static byte[] MakeBadPaddingCiphertext(AsymmetricKeyParameter recipientPublicKey)
        {
            var raw = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
            raw.Init(true, recipientPublicKey);
            byte[] block = new byte[raw.GetInputBlockSize()];
            Arrays.Fill(block, (byte)0xFF);
            return raw.ProcessBlock(block, 0, block.Length);
        }

        private static byte[] DecryptFirst(CmsEnvelopedData ed, ICipherParameters key)
        {
            foreach (RecipientInformation recipient in ed.GetRecipientInfos().GetRecipients())
                return recipient.GetContent(key);

            throw new InvalidOperationException("no recipients");
        }

        private static string TryDecryptExpectFailure(CmsEnvelopedData ed, ICipherParameters key)
        {
            try
            {
                DecryptFirst(ed, key);
                return "<decrypted-without-error>";
            }
            catch (CmsException e)
            {
                return e.Message;
            }
            catch (Exception e)
            {
                return e.GetType().Name;
            }
        }

        private static CmsEnvelopedData ReplaceKeyTransEncryptedKey(CmsEnvelopedData ed, byte[] newEncryptedKey) =>
            RebuildEnvelopedData(ed, newEncryptedKey, contentEncryptionAlgorithm: null);

        private static CmsEnvelopedData ReplaceContentAlgAndEncryptedKey(CmsEnvelopedData ed,
            DerObjectIdentifier contentEncryptionOid, byte[] newEncryptedKey) =>
            RebuildEnvelopedData(ed, newEncryptedKey, new AlgorithmIdentifier(contentEncryptionOid));

        private static CmsEnvelopedData RebuildEnvelopedData(CmsEnvelopedData ed, byte[] newEncryptedKey,
            AlgorithmIdentifier contentEncryptionAlgorithm)
        {
            Org.BouncyCastle.Asn1.Cms.ContentInfo contentInfo = ed.ContentInfo;
            var envelopedData = Org.BouncyCastle.Asn1.Cms.EnvelopedData.GetInstance(contentInfo.Content);

            var keyTrans = (Org.BouncyCastle.Asn1.Cms.KeyTransRecipientInfo)
                Org.BouncyCastle.Asn1.Cms.RecipientInfo.GetInstance(envelopedData.RecipientInfos[0]).Info;

            var newKeyTrans = new Org.BouncyCastle.Asn1.Cms.KeyTransRecipientInfo(
                keyTrans.RecipientIdentifier, keyTrans.KeyEncryptionAlgorithm, new DerOctetString(newEncryptedKey));

            var encryptedContentInfo = envelopedData.EncryptedContentInfo;
            if (contentEncryptionAlgorithm != null)
            {
                encryptedContentInfo = new Org.BouncyCastle.Asn1.Cms.EncryptedContentInfo(
                    encryptedContentInfo.ContentType, contentEncryptionAlgorithm,
                    encryptedContentInfo.EncryptedContent);
            }

            var newEnvelopedData = new Org.BouncyCastle.Asn1.Cms.EnvelopedData(
                envelopedData.OriginatorInfo,
                new DerSet(new Org.BouncyCastle.Asn1.Cms.RecipientInfo(newKeyTrans)),
                encryptedContentInfo,
                envelopedData.UnprotectedAttrs);

            return new CmsEnvelopedData(
                new Org.BouncyCastle.Asn1.Cms.ContentInfo(contentInfo.ContentType, newEnvelopedData));
        }

        private void PasswordTest(string algorithm)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddPasswordRecipient(new Pkcs5Scheme2PbeKey("password".ToCharArray(), new byte[20], 5), algorithm);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (PasswordRecipientInformation recipient in c)
            {
                CmsPbeKey key = new Pkcs5Scheme2PbeKey("password".ToCharArray(), recipient.KeyDerivationAlgorithm);

                byte[] recData = recipient.GetContent(key);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        private void PasswordUtf8Test(string algorithm)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddPasswordRecipient(
                new Pkcs5Scheme2Utf8PbeKey("abc\u5639\u563b".ToCharArray(), new byte[20], 5),
                algorithm);

            CmsEnvelopedData ed = edGen.Generate(
                new CmsProcessableByteArray(data),
                CmsEnvelopedGenerator.Aes128Cbc);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(ed.EncryptionAlgOid, CmsEnvelopedGenerator.Aes128Cbc);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (PasswordRecipientInformation recipient in c)
            {
                CmsPbeKey key = new Pkcs5Scheme2Utf8PbeKey(
                    "abc\u5639\u563b".ToCharArray(), recipient.KeyDerivationAlgorithm);

                byte[] recData = recipient.GetContent(key);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        private void VerifyECKeyAgreeVectors(AsymmetricKeyParameter privKey, string wrapAlg, byte[] message)
        {
            VerifyECKeyAgreeVectors(privKey, "1.3.133.16.840.63.0.2", wrapAlg, message);
        }

        private void VerifyECKeyAgreeVectors(AsymmetricKeyParameter privKey, string agreeAlg, string wrapAlg,
            byte[] message)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedData ed = new CmsEnvelopedData(message);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            Assert.AreEqual(wrapAlg, ed.EncryptionAlgOid);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(agreeAlg, recipient.KeyEncryptionAlgOid);

                byte[] recData = recipient.GetContent(privKey);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }

        private void VerifyECMqvKeyAgreeVectors(AsymmetricKeyParameter privKey, string wrapAlg, byte[] message)
        {
            VerifyECMqvKeyAgreeVectors(privKey, "1.3.133.16.840.63.0.16", wrapAlg, message);
        }

        private void VerifyECMqvKeyAgreeVectors(AsymmetricKeyParameter privKey, string agreeAlg, string wrapAlg,
            byte[] message)
        {
            byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

            CmsEnvelopedData ed = new CmsEnvelopedData(message);

            RecipientInformationStore recipients = ed.GetRecipientInfos();

            var c = recipients.GetRecipients();

            Assert.AreEqual(wrapAlg, ed.EncryptionAlgOid);
            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(agreeAlg, recipient.KeyEncryptionAlgOid);

                byte[] recData = recipient.GetContent(privKey);

                Assert.IsTrue(Arrays.AreEqual(data, recData));
            }
        }
    }
}
