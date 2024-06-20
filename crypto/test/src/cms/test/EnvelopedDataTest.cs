using System;
using System.Collections.Generic;
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
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
	[TestFixture]
	public class EnvelopedDataTest
	{
		private const string SignDN = "O=Bouncy Castle, C=AU";

		private static AsymmetricCipherKeyPair signKP;
//		private static X509Certificate signCert;
		//signCert = CmsTestUtil.MakeCertificate(_signKP, SignDN, _signKP, SignDN);

//		private const string OrigDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";

//		private static AsymmetricCipherKeyPair origKP;
		//origKP = CmsTestUtil.MakeKeyPair();
//		private static X509Certificate origCert;
		//origCert = CmsTestUtil.MakeCertificate(_origKP, OrigDN, _signKP, SignDN);

		private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
		private const string ReciDN2 = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";

		private static AsymmetricCipherKeyPair reciKP;
		private static X509Certificate reciCert;

		private static AsymmetricCipherKeyPair origECKP;
		private static AsymmetricCipherKeyPair reciECKP;
		private static X509Certificate reciECCert;
		private static AsymmetricCipherKeyPair reciECKP2;
		private static X509Certificate reciECCert2;

		private static AsymmetricCipherKeyPair SignKP
		{
			get { return signKP == null ? (signKP = CmsTestUtil.MakeKeyPair()) : signKP; }
		}

		private static AsymmetricCipherKeyPair ReciKP
		{
			get { return reciKP == null ? (reciKP = CmsTestUtil.MakeKeyPair()) : reciKP; }
		}

		private static X509Certificate ReciCert
		{
			get { return reciCert == null ? (reciCert = CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN)) : reciCert; }
		}

		private static AsymmetricCipherKeyPair OrigECKP
		{
			get { return origECKP == null ? (origECKP = CmsTestUtil.MakeECDsaKeyPair()) : origECKP; }
		}

		private static AsymmetricCipherKeyPair ReciECKP
		{
			get { return reciECKP == null ? (reciECKP = CmsTestUtil.MakeECDsaKeyPair()) : reciECKP; }
		}

		private static X509Certificate ReciECCert
		{
			get { return reciECCert == null ? (reciECCert = CmsTestUtil.MakeCertificate(ReciECKP, ReciDN, SignKP, SignDN)) : reciECCert; }
		}

		private static AsymmetricCipherKeyPair ReciECKP2
		{
			get { return reciECKP2 == null ? (reciECKP2 = CmsTestUtil.MakeECDsaKeyPair()) : reciECKP2; }
		}

		private static X509Certificate ReciECCert2
		{
			get { return reciECCert2 == null ? (reciECCert2 = CmsTestUtil.MakeCertificate(ReciECKP2, ReciDN2, SignKP, SignDN)) : reciECCert2; }
		}

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
            Assert.AreEqual(160, rc2P.RC2ParameterVersion.IntValueExact);

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
		public void TestKeyTransRC4()
		{
			byte[] data = Encoding.ASCII.GetBytes("WallaWallaBouncyCastle");

			CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

			edGen.AddKeyTransRecipient(ReciCert);

			CmsEnvelopedData ed = edGen.Generate(
				new CmsProcessableByteArray(data),
                PkcsObjectIdentifiers.rc4.GetID());

			RecipientInformationStore  recipients = ed.GetRecipientInfos();

			Assert.AreEqual(ed.EncryptionAlgOid, PkcsObjectIdentifiers.rc4.GetID());

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

			Assert.AreEqual(ed.EncryptionAlgOid, PkcsObjectIdentifiers.rc4.GetID());

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
		public void TestKeyTransOdes()
		{
			byte[] data = Encoding.ASCII.GetBytes("WallaWallaBouncyCastle");

			CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

			edGen.AddKeyTransRecipient(ReciCert);

			CmsEnvelopedData ed = edGen.Generate(
				new CmsProcessableByteArray(data),
				OiwObjectIdentifiers.DesCbc.Id);

			RecipientInformationStore recipients = ed.GetRecipientInfos();

			Assert.AreEqual(ed.EncryptionAlgOid, OiwObjectIdentifiers.DesCbc.Id);

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
			TryKeyTrans(CmsEnvelopedGenerator.Cast5Cbc,
				new DerObjectIdentifier(CmsEnvelopedGenerator.Cast5Cbc),
				typeof(Asn1Sequence));
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
			string				generatorOID,
			DerObjectIdentifier	checkOID,
			Type				asn1Params)
		{
			byte[] data = Encoding.ASCII.GetBytes("WallaWallaWashington");

			CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

			edGen.AddKeyTransRecipient(ReciCert);

			CmsEnvelopedData ed = edGen.Generate(new CmsProcessableByteArray(data), generatorOID);

			RecipientInformationStore recipients = ed.GetRecipientInfos();

			Assert.AreEqual(checkOID.Id, ed.EncryptionAlgOid);

			if (asn1Params != null)
			{
				Assert.IsTrue(asn1Params.IsInstanceOfType(ed.EncryptionAlgorithmID.Parameters));
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
			TryKekAlgorithm(CmsTestUtil.MakeRC2128Key(), new DerObjectIdentifier("1.2.840.113549.1.9.16.3.7"));
		}

		[Test]
		public void TestAes128Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeAesKey(128), NistObjectIdentifiers.IdAes128Wrap);
		}

		[Test]
		public void TestAes192Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeAesKey(192), NistObjectIdentifiers.IdAes192Wrap);
		}

		[Test]
		public void TestAes256Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeAesKey(256), NistObjectIdentifiers.IdAes256Wrap);
		}

		[Test]
		public void TestSeed128Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeSeedKey(), KisaObjectIdentifiers.IdNpkiAppCmsSeedWrap);
		}

		[Test]
		public void TestCamellia128Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeCamelliaKey(128), NttObjectIdentifiers.IdCamellia128Wrap);
		}

		[Test]
		public void TestCamellia192Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeCamelliaKey(192), NttObjectIdentifiers.IdCamellia192Wrap);
		}

		[Test]
		public void TestCamellia256Kek()
		{
			TryKekAlgorithm(CmsTestUtil.MakeCamelliaKey(256), NttObjectIdentifiers.IdCamellia256Wrap);
		}

		private void TryKekAlgorithm(
			KeyParameter		kek,
			DerObjectIdentifier	algOid)
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
		public void TestRfc4134Ex5_1()
		{
			byte[] data = Hex.Decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

//			KeyFactory kFact = KeyFactory.GetInstance("RSA");
//			Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));
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

//			KeyFactory kFact = KeyFactory.GetInstance("RSA");
//			Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));
			AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(bobPrivRsaEncrypt);

			CmsEnvelopedData ed = new CmsEnvelopedData(rfc4134ex5_2);

			RecipientInformationStore recipients = ed.GetRecipientInfos();

			Assert.AreEqual("1.2.840.113549.3.2", ed.EncryptionAlgOid);

			var c = recipients.GetRecipients();
			var e = c.GetEnumerator();

			if (e.MoveNext())
			{
				do
				{
					RecipientInformation recipient = e.Current;

					if (recipient is KeyTransRecipientInformation)
					{
						byte[] recData = recipient.GetContent(key);

						Assert.IsTrue(Arrays.AreEqual(data, recData));
					}
				}
				while (e.MoveNext());
			}
			else
			{
				Assert.Fail("no recipient found");
			}
		}

		[Test]
		public void TestOriginatorInfo()
		{
			CmsEnvelopedData env = new CmsEnvelopedData(CmsSampleMessages.originatorMessage);

			RecipientInformationStore  recipients = env.GetRecipientInfos();

			Assert.AreEqual(CmsEnvelopedGenerator.DesEde3Cbc, env.EncryptionAlgOid);
		}

		//[Test]
		//public void TestGost3410_2012_KeyAgree()
		//{
  //          AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(gost2012_Reci_Key);

		//	CmsEnvelopedData ed = new CmsEnvelopedData(gost2012_Reci_Msg);

		//	RecipientInformationStore recipients = ed.GetRecipientInfos();

		//	Assert.AreEqual(ed.EncryptionAlgOid, CryptoProObjectIdentifiers.GostR28147Gcfb.Id);

  //          var c = recipients.GetRecipients();

  //          Assert.AreEqual(1, c.Count);

		//	foreach (RecipientInformation recipient in c)
		//	{
		//		Assert.AreEqual(recipient.KeyEncryptionAlgOid,
		//			RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.Id);

  //              byte[] recData = recipient.GetContent(privKey);

  //              Assert.AreEqual("Hello World!", Strings.FromByteArray(recData));
		//	}

		//	var cert = new X509CertificateParser().ReadCertificate(gost2012_Reci_Cert);
  //          //CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

  //          //RecipientId id = new JceKeyAgreeRecipientId((X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gost2012_Reci_Cert)));
  // //         RecipientID id = new KeyAgreeRecipentID(cert);

		//	//var collection = recipients.GetRecipients(id);
		//	//if (collection.Count != 1)
		//	//{
		//	//	Assert.Fail("recipients not matched using general recipient ID.");
		//	//}
		//	//Assert.IsTrue(collection[0] is RecipientInformation);
		//}

		private void PasswordTest(
			string algorithm)
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

		private void PasswordUtf8Test(
			string algorithm)
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

		private void VerifyECKeyAgreeVectors(
			AsymmetricKeyParameter	privKey,
			string					wrapAlg,
			byte[]					message)
		{
			byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CmsEnvelopedData ed = new CmsEnvelopedData(message);

			RecipientInformationStore recipients = ed.GetRecipientInfos();

			Assert.AreEqual(wrapAlg, ed.EncryptionAlgOid);

			var c = recipients.GetRecipients();

			Assert.AreEqual(1, c.Count);

			foreach (RecipientInformation recipient in c)
			{
				Assert.AreEqual("1.3.133.16.840.63.0.2", recipient.KeyEncryptionAlgOid);

				byte[] recData = recipient.GetContent(privKey);

				Assert.IsTrue(Arrays.AreEqual(data, recData));
			}
		}

		private void VerifyECMqvKeyAgreeVectors(
			AsymmetricKeyParameter	privKey,
			string					wrapAlg,
			byte[]					message)
		{
			byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CmsEnvelopedData ed = new CmsEnvelopedData(message);

			RecipientInformationStore recipients = ed.GetRecipientInfos();

			var c = recipients.GetRecipients();

			Assert.AreEqual(wrapAlg, ed.EncryptionAlgOid);
			Assert.AreEqual(1, c.Count);

			foreach (RecipientInformation recipient in c)
			{
				Assert.AreEqual("1.3.133.16.840.63.0.16", recipient.KeyEncryptionAlgOid);

				byte[] recData = recipient.GetContent(privKey);

				Assert.IsTrue(Arrays.AreEqual(data, recData));
			}
		}
	}
}
