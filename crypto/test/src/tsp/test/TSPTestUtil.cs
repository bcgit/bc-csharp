using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp.Tests
{
	public class TspTestUtil
	{
		public static SecureRandom rand = new SecureRandom();
		public static IAsymmetricCipherKeyPairGenerator kpg;
		public static CipherKeyGenerator desede128kg;
		public static CipherKeyGenerator desede192kg;
		public static CipherKeyGenerator rc240kg;
		public static CipherKeyGenerator rc264kg;
		public static CipherKeyGenerator rc2128kg;
		public static BigInteger serialNumber = BigInteger.One;
		public static readonly bool Debug = true;
		public static DerObjectIdentifier EuroPkiTsaTestPolicy = new DerObjectIdentifier("1.3.6.1.4.1.5255.5.1");

		private static readonly string EncryptionECDsaWithSha1 = X9ObjectIdentifiers.ECDsaWithSha1.Id;
		private static readonly string EncryptionECDsaWithSha224 = X9ObjectIdentifiers.ECDsaWithSha224.Id;
		private static readonly string EncryptionECDsaWithSha256 = X9ObjectIdentifiers.ECDsaWithSha256.Id;
		private static readonly string EncryptionECDsaWithSha384 = X9ObjectIdentifiers.ECDsaWithSha384.Id;
		private static readonly string EncryptionECDsaWithSha512 = X9ObjectIdentifiers.ECDsaWithSha512.Id;

		public static readonly string DigestSha1 = OiwObjectIdentifiers.IdSha1.Id;
		public static readonly string DigestSha224 = NistObjectIdentifiers.IdSha224.Id;
		public static readonly string DigestSha256 = NistObjectIdentifiers.IdSha256.Id;
		public static readonly string DigestSha384 = NistObjectIdentifiers.IdSha384.Id;
		public static readonly string DigestSha512 = NistObjectIdentifiers.IdSha512.Id;
		public static readonly string DigestMD5 = PkcsObjectIdentifiers.MD5.Id;
		public static readonly string DigestGost3411 = CryptoProObjectIdentifiers.GostR3411.Id;
		public static readonly string DigestRipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128.Id;
		public static readonly string DigestRipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160.Id;
		public static readonly string DigestRipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256.Id;

		public static readonly string EncryptionRsa = PkcsObjectIdentifiers.RsaEncryption.Id;
		public static readonly string EncryptionDsa = X9ObjectIdentifiers.IdDsaWithSha1.Id;
		public static readonly string EncryptionECDsa = X9ObjectIdentifiers.ECDsaWithSha1.Id;
		public static readonly string EncryptionRsaPss = PkcsObjectIdentifiers.IdRsassaPss.Id;
		public static readonly string EncryptionGost3410 = CryptoProObjectIdentifiers.GostR3410x94.Id;
		public static readonly string EncryptionECGost3410 = CryptoProObjectIdentifiers.GostR3410x2001.Id;

		private static readonly Dictionary<string, string> EncryptionAlgs = new Dictionary<string, string>();
		private static readonly Dictionary<string, string> DigestAlgs = new Dictionary<string, string>();
		private static readonly Dictionary<string, string[]> DigestAliases = new Dictionary<string, string[]>();

		private static readonly ISet<string> NoParams = new HashSet<string>();
		private static readonly Dictionary<string, string> ECAlgorithms = new Dictionary<string, string>();

		private static void AddEntries(DerObjectIdentifier oid, string digest, string encryption)
		{
			string alias = oid.Id;
			DigestAlgs.Add(alias, digest);
			EncryptionAlgs.Add(alias, encryption);
		}

		static TspTestUtil()
		{
			rand = new SecureRandom();

			kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
			kpg.Init(new RsaKeyGenerationParameters(
				BigInteger.ValueOf(0x10001), rand, 1024, 25));

			desede128kg = GeneratorUtilities.GetKeyGenerator("DESEDE");
			desede128kg.Init(new KeyGenerationParameters(rand, 112));

			desede192kg = GeneratorUtilities.GetKeyGenerator("DESEDE");
			desede192kg.Init(new KeyGenerationParameters(rand, 168));

			rc240kg = GeneratorUtilities.GetKeyGenerator("RC2");
			rc240kg.Init(new KeyGenerationParameters(rand, 40));

			rc264kg = GeneratorUtilities.GetKeyGenerator("RC2");
			rc264kg.Init(new KeyGenerationParameters(rand, 64));

			rc2128kg = GeneratorUtilities.GetKeyGenerator("RC2");
			rc2128kg.Init(new KeyGenerationParameters(rand, 128));

			serialNumber = BigInteger.One;

			AddEntries(NistObjectIdentifiers.DsaWithSha224, "SHA224", "DSA");
			AddEntries(NistObjectIdentifiers.DsaWithSha256, "SHA256", "DSA");
			AddEntries(NistObjectIdentifiers.DsaWithSha384, "SHA384", "DSA");
			AddEntries(NistObjectIdentifiers.DsaWithSha512, "SHA512", "DSA");
			AddEntries(OiwObjectIdentifiers.DsaWithSha1, "SHA1", "DSA");
			AddEntries(OiwObjectIdentifiers.MD4WithRsa, "MD4", "RSA");
			AddEntries(OiwObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
			AddEntries(OiwObjectIdentifiers.MD5WithRsa, "MD5", "RSA");
			AddEntries(OiwObjectIdentifiers.Sha1WithRsa, "SHA1", "RSA");
			AddEntries(PkcsObjectIdentifiers.MD2WithRsaEncryption, "MD2", "RSA");
			AddEntries(PkcsObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
			AddEntries(PkcsObjectIdentifiers.MD5WithRsaEncryption, "MD5", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha1WithRsaEncryption, "SHA1", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha224WithRsaEncryption, "SHA224", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha256WithRsaEncryption, "SHA256", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha384WithRsaEncryption, "SHA384", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha512WithRsaEncryption, "SHA512", "RSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha1, "SHA1", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha224, "SHA224", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha256, "SHA256", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha384, "SHA384", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha512, "SHA512", "ECDSA");
			AddEntries(X9ObjectIdentifiers.IdDsaWithSha1, "SHA1", "DSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");

			EncryptionAlgs.Add(X9ObjectIdentifiers.IdDsa.Id, "DSA");
			EncryptionAlgs.Add(PkcsObjectIdentifiers.RsaEncryption.Id, "RSA");
			EncryptionAlgs.Add(TeleTrusTObjectIdentifiers.TeleTrusTRsaSignatureAlgorithm.Id, "RSA");
			EncryptionAlgs.Add(X509ObjectIdentifiers.IdEARsa.Id, "RSA");
			EncryptionAlgs.Add(EncryptionRsaPss, "RSAandMGF1");
			EncryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x94.Id, "GOST3410");
			EncryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x2001.Id, "ECGOST3410");
			EncryptionAlgs.Add("1.3.6.1.4.1.5849.1.6.2", "ECGOST3410");
			EncryptionAlgs.Add("1.3.6.1.4.1.5849.1.1.5", "GOST3410");

			DigestAlgs.Add(PkcsObjectIdentifiers.MD2.Id, "MD2");
			DigestAlgs.Add(PkcsObjectIdentifiers.MD4.Id, "MD4");
			DigestAlgs.Add(PkcsObjectIdentifiers.MD5.Id, "MD5");
			DigestAlgs.Add(OiwObjectIdentifiers.IdSha1.Id, "SHA1");
			DigestAlgs.Add(NistObjectIdentifiers.IdSha224.Id, "SHA224");
			DigestAlgs.Add(NistObjectIdentifiers.IdSha256.Id, "SHA256");
			DigestAlgs.Add(NistObjectIdentifiers.IdSha384.Id, "SHA384");
			DigestAlgs.Add(NistObjectIdentifiers.IdSha512.Id, "SHA512");
			DigestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD128.Id, "RIPEMD128");
			DigestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD160.Id, "RIPEMD160");
			DigestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD256.Id, "RIPEMD256");
			DigestAlgs.Add(CryptoProObjectIdentifiers.GostR3411.Id, "GOST3411");
			DigestAlgs.Add("1.3.6.1.4.1.5849.1.2.1", "GOST3411");

			DigestAliases.Add("SHA1", new string[] { "SHA-1" });
			DigestAliases.Add("SHA224", new string[] { "SHA-224" });
			DigestAliases.Add("SHA256", new string[] { "SHA-256" });
			DigestAliases.Add("SHA384", new string[] { "SHA-384" });
			DigestAliases.Add("SHA512", new string[] { "SHA-512" });

			NoParams.Add(EncryptionDsa);
			//noParams.Add(EncryptionECDsa);
			NoParams.Add(EncryptionECDsaWithSha1);
			NoParams.Add(EncryptionECDsaWithSha224);
			NoParams.Add(EncryptionECDsaWithSha256);
			NoParams.Add(EncryptionECDsaWithSha384);
			NoParams.Add(EncryptionECDsaWithSha512);

			ECAlgorithms.Add(DigestSha1, EncryptionECDsaWithSha1);
			ECAlgorithms.Add(DigestSha224, EncryptionECDsaWithSha224);
			ECAlgorithms.Add(DigestSha256, EncryptionECDsaWithSha256);
			ECAlgorithms.Add(DigestSha384, EncryptionECDsaWithSha384);
			ECAlgorithms.Add(DigestSha512, EncryptionECDsaWithSha512);
		}

		public static string DumpBase64(
			byte[] data)
		{
			StringBuilder buf = new StringBuilder();

			data = Base64.Encode(data);

			for (int i = 0; i < data.Length; i += 64)
			{
				if (i + 64 < data.Length)
				{
					buf.AppendLine(Encoding.ASCII.GetString(data, i, 64));
				}
				else
				{
					buf.AppendLine(Encoding.ASCII.GetString(data, i, data.Length - i));
				}
			}

			return buf.ToString();
		}

		public static string GetDigestAlgName(string digestAlgOid)
		{
			return CollectionUtilities.GetValueOrKey(DigestAlgs, digestAlgOid);
		}

		public static string GetEncryptionAlgName(string encryptionAlgOid)
		{
			return CollectionUtilities.GetValueOrKey(EncryptionAlgs, encryptionAlgOid);
		}

		internal static string GetEncOid(AsymmetricKeyParameter key, string digestOID)
		{
			string encOID;

			if (key is RsaKeyParameters)
			{
				if (!((RsaKeyParameters)key).IsPrivate)
					throw new ArgumentException("Expected RSA private key");

				encOID = EncryptionRsa;
			}
			else if (key is DsaPrivateKeyParameters)
			{
				if (digestOID.Equals(DigestSha1))
				{
					encOID = EncryptionDsa;
				}
				else if (digestOID.Equals(DigestSha224))
				{
					encOID = NistObjectIdentifiers.DsaWithSha224.Id;
				}
				else if (digestOID.Equals(DigestSha256))
				{
					encOID = NistObjectIdentifiers.DsaWithSha256.Id;
				}
				else if (digestOID.Equals(DigestSha384))
				{
					encOID = NistObjectIdentifiers.DsaWithSha384.Id;
				}
				else if (digestOID.Equals(DigestSha512))
				{
					encOID = NistObjectIdentifiers.DsaWithSha512.Id;
				}
				else
				{
					throw new ArgumentException("can't mix DSA with anything but SHA1/SHA2");
				}
			}
			else if (key is ECPrivateKeyParameters)
			{
				ECPrivateKeyParameters ecPrivKey = (ECPrivateKeyParameters)key;
				string algName = ecPrivKey.AlgorithmName;

				if (algName == "ECGOST3410")
				{
					encOID = EncryptionECGost3410;
				}
				else
				{
					// TODO Should we insist on algName being one of "EC" or "ECDSA", as Java does?
					if (!ECAlgorithms.TryGetValue(digestOID, out encOID))
						throw new ArgumentException("can't mix ECDSA with anything but SHA family digests");
				}
			}
			else if (key is Gost3410PrivateKeyParameters)
			{
				encOID = EncryptionGost3410;
			}
			else
			{
				throw new ArgumentException("Unknown algorithm in CmsSignedGenerator.GetEncOid");
			}

			return encOID;
		}

		public static AsymmetricCipherKeyPair MakeKeyPair()
		{
			return kpg.GenerateKeyPair();
		}

		public static KeyParameter MakeDesede128Key()
		{
			return new DesEdeParameters(desede128kg.GenerateKey());
		}

		public static KeyParameter MakeDesede192Key()
		{
			return new DesEdeParameters(desede192kg.GenerateKey());
		}

		public static KeyParameter MakeRC240Key()
		{
			return new RC2Parameters(rc240kg.GenerateKey());
		}

		public static KeyParameter MakeRC264Key()
		{
			return new RC2Parameters(rc264kg.GenerateKey());
		}

		public static KeyParameter MakeRC2128Key()
		{
			return new RC2Parameters(rc2128kg.GenerateKey());
		}

		public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair _subKP,
			string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN)
		{
			return MakeCertificate(_subKP, _subDN, _issKP, _issDN, false);
		}

		public static X509Certificate MakeCACertificate(AsymmetricCipherKeyPair _subKP,
			string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN)
		{
			return MakeCertificate(_subKP, _subDN, _issKP, _issDN, true);
		}

		public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair _subKP,
			string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN, bool _ca)
		{
			AsymmetricKeyParameter _subPub = _subKP.Public;
			AsymmetricKeyParameter _issPriv = _issKP.Private;
			AsymmetricKeyParameter _issPub = _issKP.Public;

			X509V3CertificateGenerator _v3CertGen = new X509V3CertificateGenerator();

			_v3CertGen.Reset();
			_v3CertGen.SetSerialNumber(allocateSerialNumber());
			_v3CertGen.SetIssuerDN(new X509Name(_issDN));
			_v3CertGen.SetNotBefore(DateTime.UtcNow);
			_v3CertGen.SetNotAfter(DateTime.UtcNow.AddDays(100));
			_v3CertGen.SetSubjectDN(new X509Name(_subDN));
			_v3CertGen.SetPublicKey(_subPub);

			_v3CertGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
					createSubjectKeyId(_subPub));

			_v3CertGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
					createAuthorityKeyId(_issPub));

			if (_ca)
			{
				_v3CertGen.AddExtension(X509Extensions.BasicConstraints, false,
						new BasicConstraints(_ca));
			}
			else
			{
				_v3CertGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
					ExtendedKeyUsage.GetInstance(new DerSequence(KeyPurposeID.id_kp_timeStamping)));
			}

            X509Certificate _cert = _v3CertGen.Generate(
				new Asn1SignatureFactory("MD5WithRSAEncryption", _issPriv, null));

            _cert.CheckValidity(DateTime.UtcNow);
			_cert.Verify(_issPub);

			return _cert;
		}

		/*
		*
		*  INTERNAL METHODS
		*
		*/
		private static AuthorityKeyIdentifier createAuthorityKeyId(
			AsymmetricKeyParameter _pubKey)
		{
			return new AuthorityKeyIdentifier(
				SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_pubKey));
		}

//		private static AuthorityKeyIdentifier createAuthorityKeyId(
//			AsymmetricKeyParameter _pubKey, X509Name _name, int _sNumber)
//		{
//			SubjectPublicKeyInfo _info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_pubKey);
//
//			GeneralName _genName = new GeneralName(_name);
//
//			return new AuthorityKeyIdentifier(_info, GeneralNames.GetInstance(
//				new DerSequence(_genName)), BigInteger.ValueOf(_sNumber));
//		}

		private static SubjectKeyIdentifier createSubjectKeyId(
			AsymmetricKeyParameter _pubKey)
		{
			return new SubjectKeyIdentifier(
				SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_pubKey));
		}

		private static BigInteger allocateSerialNumber()
		{
			BigInteger _tmp = serialNumber;
			serialNumber = serialNumber.Add(BigInteger.One);
			return _tmp;
		}
	}
}