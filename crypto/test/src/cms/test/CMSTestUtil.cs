using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Cms.Tests
{
    public class CmsTestUtil
	{
		public static readonly SecureRandom Random = new SecureRandom();

		private static IAsymmetricCipherKeyPairGenerator kpg;
		private static IAsymmetricCipherKeyPairGenerator gostKpg;
		private static IAsymmetricCipherKeyPairGenerator dsaKpg;
		private static IAsymmetricCipherKeyPairGenerator ecGostKpg;
		private static IAsymmetricCipherKeyPairGenerator ecDsaKpg;
        private static IAsymmetricCipherKeyPairGenerator ed25519Kpg;
        private static IAsymmetricCipherKeyPairGenerator ed448Kpg;
        private static IAsymmetricCipherKeyPairGenerator mlDsa44Kpg;
        private static IAsymmetricCipherKeyPairGenerator mlDsa65Kpg;
        private static IAsymmetricCipherKeyPairGenerator mlDsa87Kpg;
        private static IAsymmetricCipherKeyPairGenerator mlKem512Kpg;
        private static IAsymmetricCipherKeyPairGenerator mlKem768Kpg;
        private static IAsymmetricCipherKeyPairGenerator mlKem1024Kpg;

        public static CipherKeyGenerator aes128KG;
        public static CipherKeyGenerator aes192KG;
        public static CipherKeyGenerator aes256KG;
        public static CipherKeyGenerator camellia128KG;
        public static CipherKeyGenerator camellia192KG;
        public static CipherKeyGenerator camellia256KG;
        public static CipherKeyGenerator desede128KG;
		public static CipherKeyGenerator desede192KG;
		public static CipherKeyGenerator rc2_40KG;
		public static CipherKeyGenerator rc2_64KG;
		public static CipherKeyGenerator rc2_128KG;
		public static CipherKeyGenerator seedKG;

		public static int serialNumber;

		private static readonly byte[] attrCert = Base64.Decode(
			  "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
			+ "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
			+ "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
			+ "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
			+ "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
			+ "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
			+ "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
			+ "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
			+ "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
			+ "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
			+ "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
			+ "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
			+ "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
			+ "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
			+ "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
			+ "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
			+ "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
			+ "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
			+ "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
			+ "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
			+ "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
			+ "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
			+ "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
			+ "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
			+ "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
			+ "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
			+ "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
			+ "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
			+ "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
			+ "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
			+ "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
			+ "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
			+ "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
			+ "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
			+ "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
			+ "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
			+ "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
			+ "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
			+ "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

        internal static X509Certificate InitCertificate(ref X509Certificate certificate,
			Func<X509Certificate> initialize)
        {
            var current = Volatile.Read(ref certificate);
            if (null != current)
                return current;

            var candidate = initialize();

            return Interlocked.CompareExchange(ref certificate, candidate, null) ?? candidate;
        }

        internal static X509Crl InitCrl(ref X509Crl crl, Func<X509Crl> initialize)
        {
            var current = Volatile.Read(ref crl);
            if (null != current)
                return current;

            var candidate = initialize();

            return Interlocked.CompareExchange(ref crl, candidate, null) ?? candidate;
        }

        internal static AsymmetricCipherKeyPair InitKP(ref AsymmetricCipherKeyPair kp,
            Func<AsymmetricCipherKeyPair> initialize)
        {
            var current = Volatile.Read(ref kp);
            if (null != current)
                return current;

            var candidate = initialize();

            return Interlocked.CompareExchange(ref kp, candidate, null) ?? candidate;
        }

        private static IAsymmetricCipherKeyPairGenerator InitKpg(ref IAsymmetricCipherKeyPairGenerator kpg,
			string algorithm, Func<KeyGenerationParameters> createParameters)
        {
            var current = Volatile.Read(ref kpg);
            if (null != current)
                return current;

			var candidate = GeneratorUtilities.GetKeyPairGenerator(algorithm);
			candidate.Init(createParameters());

            return Interlocked.CompareExchange(ref kpg, candidate, null) ?? candidate;
        }

		private static IAsymmetricCipherKeyPairGenerator Kpg => InitKpg(ref kpg, "RSA", () =>
			new RsaKeyGenerationParameters(BigInteger.ValueOf(17), Random, 1024, 25));

        private static IAsymmetricCipherKeyPairGenerator GostKpg => InitKpg(ref gostKpg, "GOST3410", () =>
            new Gost3410KeyGenerationParameters(Random, CryptoProObjectIdentifiers.GostR3410x94CryptoProA));

        private static IAsymmetricCipherKeyPairGenerator DsaKpg => InitKpg(ref dsaKpg, "DSA", () =>
		{
            DsaParameters dsaSpec = new DsaParameters(
                new BigInteger("7434410770759874867539421675728577177024889699586189000788950934679315164676852047058354758883833299702695428196962057871264685291775577130504050839126673"),
                new BigInteger("1138656671590261728308283492178581223478058193247"),
                new BigInteger("4182906737723181805517018315469082619513954319976782448649747742951189003482834321192692620856488639629011570381138542789803819092529658402611668375788410"));
            return new DsaKeyGenerationParameters(Random, dsaSpec);
        });

        private static IAsymmetricCipherKeyPairGenerator ECGostKpg => InitKpg(ref ecGostKpg, "ECGOST3410", () =>
            new ECKeyGenerationParameters(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA, Random));

        private static IAsymmetricCipherKeyPairGenerator ECDsaKpg => InitKpg(ref ecDsaKpg, "ECDSA", () =>
            new KeyGenerationParameters(Random, 239));

		private static IAsymmetricCipherKeyPairGenerator Ed25519Kpg => InitKpg(ref ed25519Kpg, "Ed25519", () =>
			new Ed25519KeyGenerationParameters(Random));

        private static IAsymmetricCipherKeyPairGenerator Ed448Kpg => InitKpg(ref ed448Kpg, "Ed448", () =>
            new Ed448KeyGenerationParameters(Random));

        private static IAsymmetricCipherKeyPairGenerator MLDsa44Kpg => InitKpg(ref mlDsa44Kpg, "ML-DSA-44", () =>
			new MLDsaKeyGenerationParameters(Random, NistObjectIdentifiers.id_ml_dsa_44));

        private static IAsymmetricCipherKeyPairGenerator MLDsa65Kpg => InitKpg(ref mlDsa65Kpg, "ML-DSA-65", () =>
            new MLDsaKeyGenerationParameters(Random, NistObjectIdentifiers.id_ml_dsa_44));

        private static IAsymmetricCipherKeyPairGenerator MLDsa87Kpg => InitKpg(ref mlDsa87Kpg, "ML-DSA-87", () =>
            new MLDsaKeyGenerationParameters(Random, NistObjectIdentifiers.id_ml_dsa_44));

        private static IAsymmetricCipherKeyPairGenerator MLKem512Kpg => InitKpg(ref mlKem512Kpg, "ML-KEM-512", () =>
            new MLKemKeyGenerationParameters(Random, NistObjectIdentifiers.id_alg_ml_kem_512));

        private static IAsymmetricCipherKeyPairGenerator MLKem768Kpg => InitKpg(ref mlKem768Kpg, "ML-KEM-768", () =>
            new MLKemKeyGenerationParameters(Random, NistObjectIdentifiers.id_alg_ml_kem_768));

        private static IAsymmetricCipherKeyPairGenerator MLKem1024Kpg => InitKpg(ref mlKem1024Kpg, "ML-KEM-1024", () =>
            new MLKemKeyGenerationParameters(Random, NistObjectIdentifiers.id_alg_ml_kem_1024));

        private static int NextSerialNumber() => Interlocked.Increment(ref serialNumber);

        static CmsTestUtil()
		{
            aes128KG = GeneratorUtilities.GetKeyGenerator("AES");
            aes128KG.Init(new KeyGenerationParameters(Random, 128));

            aes192KG = GeneratorUtilities.GetKeyGenerator("AES");
			aes192KG.Init(new KeyGenerationParameters(Random, 192));

            aes256KG = GeneratorUtilities.GetKeyGenerator("AES");
            aes256KG.Init(new KeyGenerationParameters(Random, 256));

            camellia128KG = GeneratorUtilities.GetKeyGenerator("Camellia");
            camellia128KG.Init(new KeyGenerationParameters(Random, 128));

            camellia192KG = GeneratorUtilities.GetKeyGenerator("Camellia");
            camellia192KG.Init(new KeyGenerationParameters(Random, 192));

            camellia256KG = GeneratorUtilities.GetKeyGenerator("Camellia");
            camellia256KG.Init(new KeyGenerationParameters(Random, 256));

            desede128KG = GeneratorUtilities.GetKeyGenerator("DESEDE");
			desede128KG.Init(new KeyGenerationParameters(Random, 112));

			desede192KG = GeneratorUtilities.GetKeyGenerator("DESEDE");
			desede192KG.Init(new KeyGenerationParameters(Random, 168));

			rc2_40KG = GeneratorUtilities.GetKeyGenerator("RC2");
			rc2_40KG.Init(new KeyGenerationParameters(Random, 40));

			rc2_64KG = GeneratorUtilities.GetKeyGenerator("RC2");
			rc2_64KG.Init(new KeyGenerationParameters(Random, 64));

			rc2_128KG = GeneratorUtilities.GetKeyGenerator("RC2");
			rc2_128KG.Init(new KeyGenerationParameters(Random, 128));

			seedKG = GeneratorUtilities.GetKeyGenerator("SEED");

			serialNumber = 0;
		}

		public static string DumpBase64(byte[] data)
		{
			StringBuilder buf = new StringBuilder();

			data = Base64.Encode(data);

			for (int i = 0; i < data.Length; i += 64)
			{
				if (i + 64 < data.Length)
				{
					buf.Append(Encoding.ASCII.GetString(data, i, 64));
				}
				else
				{
					buf.Append(Encoding.ASCII.GetString(data, i, data.Length - i));
				}
				buf.AppendLine();
			}

			return buf.ToString();
		}

		public static X509V2AttributeCertificate GetAttributeCertificate() =>
			new X509AttrCertParser().ReadAttrCert(attrCert);

        public static AsymmetricCipherKeyPair MakeKeyPair() => Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeGostKeyPair() => GostKpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeDsaKeyPair() => DsaKpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeECGostKeyPair() => ECGostKpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeECDsaKeyPair() => ECDsaKpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeEd25519KeyPair() => Ed25519Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeEd448KeyPair() => Ed448Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeMLDsa44KeyPair() => MLDsa44Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeMLDsa65KeyPair() => MLDsa65Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeMLDsa87KeyPair() => MLDsa87Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeMLKem512KeyPair() => MLKem512Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeMLKem768KeyPair() => MLKem768Kpg.GenerateKeyPair();

        public static AsymmetricCipherKeyPair MakeMLKem1024KeyPair() => MLKem1024Kpg.GenerateKeyPair();

        public static KeyParameter MakeAes128Key() =>
            ParameterUtilities.CreateKeyParameter("AES", aes128KG.GenerateKey());

        public static KeyParameter MakeAes192Key() =>
            ParameterUtilities.CreateKeyParameter("AES", aes192KG.GenerateKey());

        public static KeyParameter MakeAes256Key() =>
            ParameterUtilities.CreateKeyParameter("AES", aes256KG.GenerateKey());

        public static KeyParameter MakeCamellia128Key() =>
            ParameterUtilities.CreateKeyParameter("CAMELLIA", camellia128KG.GenerateKey());

        public static KeyParameter MakeCamellia192Key() =>
            ParameterUtilities.CreateKeyParameter("CAMELLIA", camellia192KG.GenerateKey());

        public static KeyParameter MakeCamellia256Key() =>
            ParameterUtilities.CreateKeyParameter("CAMELLIA", camellia256KG.GenerateKey());

        public static KeyParameter MakeDesEde128Key() =>
            ParameterUtilities.CreateKeyParameter("DESEDE", desede128KG.GenerateKey());

		public static KeyParameter MakeDesEde192Key() =>
			ParameterUtilities.CreateKeyParameter("DESEDE", desede192KG.GenerateKey());

		public static KeyParameter MakeRC2_40Key() =>
			ParameterUtilities.CreateKeyParameter("RC2", rc2_40KG.GenerateKey());

		public static KeyParameter MakeRC2_64Key() =>
			ParameterUtilities.CreateKeyParameter("RC2", rc2_64KG.GenerateKey());

		public static KeyParameter MakeRC2_128Key() =>
			ParameterUtilities.CreateKeyParameter("RC2", rc2_128KG.GenerateKey());

		public static KeyParameter MakeSeedKey() =>
			ParameterUtilities.CreateKeyParameter("SEED", seedKG.GenerateKey());

		public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair _subKP, string _subDN,
			AsymmetricCipherKeyPair _issKP, string _issDN)
		{
			return MakeCertificate(_subKP, _subDN, _issKP, _issDN, false);
		}

		public static X509Certificate MakeCACertificate(AsymmetricCipherKeyPair _subKP, string _subDN,
			AsymmetricCipherKeyPair _issKP, string _issDN)
		{
			return MakeCertificate(_subKP, _subDN, _issKP, _issDN, true);
		}

		public static X509Certificate MakeV1Certificate(AsymmetricCipherKeyPair subKP, string _subDN,
			AsymmetricCipherKeyPair issKP, string _issDN)
		{
			AsymmetricKeyParameter subPub = subKP.Public;
			AsymmetricKeyParameter issPriv = issKP.Private;
			AsymmetricKeyParameter issPub = issKP.Public;

			string signatureAlgorithm = GetSignatureAlgorithm(issPub);
			ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issPriv, Random);

			X509V1CertificateGenerator v1CertGen = new X509V1CertificateGenerator();
			v1CertGen.Reset();
			v1CertGen.SetSerialNumber(AllocateSerialNumber());
			v1CertGen.SetIssuerDN(new X509Name(_issDN));
			v1CertGen.SetNotBefore(DateTime.UtcNow);
			v1CertGen.SetNotAfter(DateTime.UtcNow.AddDays(100));
			v1CertGen.SetSubjectDN(new X509Name(_subDN));
			v1CertGen.SetPublicKey(subPub);
			X509Certificate _cert = v1CertGen.Generate(signatureFactory);

			_cert.CheckValidity(DateTime.UtcNow);
			_cert.Verify(issPub);

			return _cert;
		}

		public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair subKP, string _subDN,
			AsymmetricCipherKeyPair issKP, string _issDN, bool _ca)
		{
			AsymmetricKeyParameter subPub = subKP.Public;
			AsymmetricKeyParameter issPriv = issKP.Private;
			AsymmetricKeyParameter issPub = issKP.Public;

			string signatureAlgorithm = GetSignatureAlgorithm(issPub);
			ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issPriv, Random);

			X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
			v3CertGen.Reset();
			v3CertGen.SetSerialNumber(AllocateSerialNumber());
			v3CertGen.SetIssuerDN(new X509Name(_issDN));
			v3CertGen.SetNotBefore(DateTime.UtcNow);
			v3CertGen.SetNotAfter(DateTime.UtcNow.AddDays(100));
			v3CertGen.SetSubjectDN(new X509Name(_subDN));
			v3CertGen.SetPublicKey(subPub);

			v3CertGen.AddExtension(
				X509Extensions.SubjectKeyIdentifier,
				false,
				CreateSubjectKeyID(subPub));

			v3CertGen.AddExtension(
				X509Extensions.AuthorityKeyIdentifier,
				false,
				CreateAuthorityKeyID(issPub));

			v3CertGen.AddExtension(
				X509Extensions.BasicConstraints,
				false,
				new BasicConstraints(_ca));

			X509Certificate _cert = v3CertGen.Generate(signatureFactory);

			_cert.CheckValidity();
			_cert.Verify(issPub);

			return _cert;
		}

		public static X509Crl MakeCrl(AsymmetricCipherKeyPair pair)
		{
			X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
			DateTime now = DateTime.UtcNow;

			crlGen.SetIssuerDN(new X509Name("CN=Test CA"));

			crlGen.SetThisUpdate(now);
			crlGen.SetNextUpdate(now.AddSeconds(100));

			crlGen.AddCrlEntry(BigInteger.One, now, CrlReason.PrivilegeWithdrawn);

			crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(pair.Public));

			return crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", pair.Private, Random));
		}

        /*
		*
		*  INTERNAL METHODS
		*
		*/

        internal static string GetSignatureAlgorithm(AsymmetricKeyParameter publicKey)
        {
            /*
             * NOTE: Current ALL test certificates are issued under a SHA1withRSA root, so these are mostly redundant.
             */

            if (publicKey is RsaKeyParameters)
                return "SHA1WithRSA";

            if (publicKey is DsaPublicKeyParameters)
                return "SHA1withDSA";

            if (publicKey is ECPublicKeyParameters ecPub)
                return ecPub.AlgorithmName == "ECGOST3410" ? "GOST3411withECGOST3410" : "SHA1withECDSA";

            if (publicKey is Gost3410PublicKeyParameters)
                return "GOST3411WithGOST3410";

            if (publicKey is Ed25519PublicKeyParameters)
                return "Ed25519";

            if (publicKey is Ed448PublicKeyParameters)
                return "Ed448";

            if (publicKey is MLDsaPublicKeyParameters mlDsa)
                return mlDsa.Parameters.Name;

            throw new NotSupportedException("Algorithm handlers incomplete");
        }

        internal static IStore<X509V2AttributeCertificate> MakeAttrCertStore(
			params X509V2AttributeCertificate[] attrCerts)
        {
			var attrCertList = new List<X509V2AttributeCertificate>();
			foreach (var attrCert in attrCerts)
            {
                attrCertList.Add(attrCert);
            }

			return CollectionUtilities.CreateStore(attrCertList);
        }

        internal static IStore<X509Certificate> MakeCertStore(params X509Certificate[] certs)
        {
            var certList = new List<X509Certificate>();
            foreach (var cert in certs)
            {
                certList.Add(cert);
            }

			return CollectionUtilities.CreateStore(certList);
        }

        internal static IStore<X509Crl> MakeCrlStore(params X509Crl[] crls)
        {
            var crlList = new List<X509Crl>();
            foreach (var crl in crls)
            {
                crlList.Add(crl);
            }

			return CollectionUtilities.CreateStore(crlList);
        }

        internal static IStore<Asn1Encodable> MakeOtherRevocationInfoStore(byte[] ocspResponseBytes)
        {
            var otherRevocationInfoList = new List<Asn1Encodable>
            {
                Asn1Object.FromByteArray(ocspResponseBytes)
            };
            return CollectionUtilities.CreateStore(otherRevocationInfoList);
        }

        internal static AuthorityKeyIdentifier CreateAuthorityKeyID(AsymmetricKeyParameter pubKey) =>
            new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey));

        internal static SubjectKeyIdentifier CreateSubjectKeyID(AsymmetricKeyParameter pubKey) =>
            new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey));

        private static BigInteger AllocateSerialNumber() => BigInteger.ValueOf(NextSerialNumber());

        public static byte[] StreamToByteArray(Stream inStream) => Streams.ReadAll(inStream);
    }
}
