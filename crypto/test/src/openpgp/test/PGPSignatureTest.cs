using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
	[TestFixture]
	public class PgpSignatureTest
		: SimpleTest
	{
		private const int[] NO_PREFERENCES = null;
		private static readonly int[] PREFERRED_SYMMETRIC_ALGORITHMS
			= new int[] { (int)SymmetricKeyAlgorithmTag.Aes128, (int)SymmetricKeyAlgorithmTag.TripleDes };
		private static readonly int[] PREFERRED_HASH_ALGORITHMS
			= new int[] { (int)HashAlgorithmTag.Sha1, (int)HashAlgorithmTag.Sha256 };
		private static readonly int[] PREFERRED_COMPRESSION_ALGORITHMS
			= new int[] { (int)CompressionAlgorithmTag.ZLib };

		private const int TEST_EXPIRATION_TIME = 10000;
		private const string TEST_USER_ID = "test user id";
		private static readonly byte[] TEST_DATA = Encoding.ASCII.GetBytes("hello world!\nhello world!\n");
		private static readonly byte[] TEST_DATA_WITH_CRLF = Encoding.ASCII.GetBytes("hello world!\r\nhello world!\r\n");

		private static readonly byte[] dsaKeyRing = Base64.Decode(
			"lQHhBD9HBzURBACzkxRCVGJg5+Ld9DU4Xpnd4LCKgMq7YOY7Gi0EgK92gbaa6+zQ"
			+ "oQFqz1tt3QUmpz3YVkm/zLESBBtC1ACIXGggUdFMUr5I87+1Cb6vzefAtGt8N5VV"
			+ "1F/MXv1gJz4Bu6HyxL/ncfe71jsNhav0i4yAjf2etWFj53zK6R+Ojg5H6wCgpL9/"
			+ "tXVfGP8SqFvyrN/437MlFSUEAIN3V6j/MUllyrZglrtr2+RWIwRrG/ACmrF6hTug"
			+ "Ol4cQxaDYNcntXbhlTlJs9MxjTH3xxzylyirCyq7HzGJxZzSt6FTeh1DFYzhJ7Qu"
			+ "YR1xrSdA6Y0mUv0ixD5A4nPHjupQ5QCqHGeRfFD/oHzD4zqBnJp/BJ3LvQ66bERJ"
			+ "mKl5A/4uj3HoVxpb0vvyENfRqKMmGBISycY4MoH5uWfb23FffsT9r9KL6nJ4syLz"
			+ "aRR0gvcbcjkc9Z3epI7gr3jTrb4d8WPxsDbT/W1tv9bG/EHawomLcihtuUU68Uej"
			+ "6/wZot1XJqu2nQlku57+M/V2X1y26VKsipolPfja4uyBOOyvbP4DAwIDIBTxWjkC"
			+ "GGAWQO2jy9CTvLHJEoTO7moHrp1FxOVpQ8iJHyRqZzLllO26OzgohbiPYz8u9qCu"
			+ "lZ9Xn7QzRXJpYyBFY2hpZG5hIChEU0EgVGVzdCBLZXkpIDxlcmljQGJvdW5jeWNh"
			+ "c3RsZS5vcmc+iFkEExECABkFAj9HBzUECwcDAgMVAgMDFgIBAh4BAheAAAoJEM0j"
			+ "9enEyjRDAlwAnjTjjt57NKIgyym7OTCwzIU3xgFpAJ0VO5m5PfQKmGJRhaewLSZD"
			+ "4nXkHg==");

		private static readonly char[] dsaPass = "hello world".ToCharArray();

		private static readonly byte[] rsaKeyRing = Base64.Decode(
			  "lQIEBEBXUNMBBADScQczBibewnbCzCswc/9ut8R0fwlltBRxMW0NMdKJY2LF"
			+ "7k2COeLOCIU95loJGV6ulbpDCXEO2Jyq8/qGw1qD3SCZNXxKs3GS8Iyh9Uwd"
			+ "VL07nMMYl5NiQRsFB7wOb86+94tYWgvikVA5BRP5y3+O3GItnXnpWSJyREUy"
			+ "6WI2QQAGKf4JAwIVmnRs4jtTX2DD05zy2mepEQ8bsqVAKIx7lEwvMVNcvg4Y"
			+ "8vFLh9Mf/uNciwL4Se/ehfKQ/AT0JmBZduYMqRU2zhiBmxj4cXUQ0s36ysj7"
			+ "fyDngGocDnM3cwPxaTF1ZRBQHSLewP7dqE7M73usFSz8vwD/0xNOHFRLKbsO"
			+ "RqDlLA1Cg2Yd0wWPS0o7+qqk9ndqrjjSwMM8ftnzFGjShAdg4Ca7fFkcNePP"
			+ "/rrwIH472FuRb7RbWzwXA4+4ZBdl8D4An0dwtfvAO+jCZSrLjmSpxEOveJxY"
			+ "GduyR4IA4lemvAG51YHTHd4NXheuEqsIkn1yarwaaj47lFPnxNOElOREMdZb"
			+ "nkWQb1jfgqO24imEZgrLMkK9bJfoDnlF4k6r6hZOp5FSFvc5kJB4cVo1QJl4"
			+ "pwCSdoU6luwCggrlZhDnkGCSuQUUW45NE7Br22NGqn4/gHs0KCsWbAezApGj"
			+ "qYUCfX1bcpPzUMzUlBaD5rz2vPeO58CDtBJ0ZXN0ZXIgPHRlc3RAdGVzdD6I"
			+ "sgQTAQIAHAUCQFdQ0wIbAwQLBwMCAxUCAwMWAgECHgECF4AACgkQs8JyyQfH"
			+ "97I1QgP8Cd+35maM2cbWV9iVRO+c5456KDi3oIUSNdPf1NQrCAtJqEUhmMSt"
			+ "QbdiaFEkPrORISI/2htXruYn0aIpkCfbUheHOu0sef7s6pHmI2kOQPzR+C/j"
			+ "8D9QvWsPOOso81KU2axUY8zIer64Uzqc4szMIlLw06c8vea27RfgjBpSCryw"
			+ "AgAA");

		private static readonly char[] rsaPass = "2002 Buffalo Sabres".ToCharArray();

		private static readonly byte[] nullPacketsSubKeyBinding = Base64.Decode(
			"iDYEGBECAAAAACp9AJ9PlJCrFpi+INwG7z61eku2Wg1HaQCgl33X5Egj+Kf7F9CXIWj2iFCvQDo=");

		public override void PerformTest()
		{
			//
			// RSA tests
			//
			PgpSecretKeyRing pgpPriv = new PgpSecretKeyRing(rsaKeyRing);
			PgpSecretKey secretKey = pgpPriv.GetSecretKey();
			PgpPrivateKey pgpPrivKey = secretKey.ExtractPrivateKey(rsaPass);

			try
			{
				doTestSig(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);

				Fail("RSA wrong key test failed.");
			}
			catch (PgpException)
			{
				// expected
			}

			try
			{
				doTestSigV3(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);

				Fail("RSA V3 wrong key test failed.");
			}
			catch (PgpException)
			{
				// expected
			}

			//
			// certifications
			//
			PgpSignatureGenerator sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1);

			sGen.InitSign(PgpSignature.KeyRevocation, pgpPrivKey);

			PgpSignature sig = sGen.GenerateCertification(secretKey.PublicKey);

			sig.InitVerify(secretKey.PublicKey);

			if (!sig.VerifyCertification(secretKey.PublicKey))
			{
				Fail("revocation verification failed.");
			}

			PgpSecretKeyRing pgpDSAPriv = new PgpSecretKeyRing(dsaKeyRing);
			PgpSecretKey secretDSAKey = pgpDSAPriv.GetSecretKey();
			PgpPrivateKey pgpPrivDSAKey = secretDSAKey.ExtractPrivateKey(dsaPass);

			sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1);

			sGen.InitSign(PgpSignature.SubkeyBinding, pgpPrivDSAKey);

			PgpSignatureSubpacketGenerator    unhashedGen = new PgpSignatureSubpacketGenerator();
			PgpSignatureSubpacketGenerator    hashedGen = new PgpSignatureSubpacketGenerator();

			hashedGen.SetSignatureExpirationTime(false, TEST_EXPIRATION_TIME);
			hashedGen.SetSignerUserId(true, TEST_USER_ID);
			hashedGen.SetPreferredCompressionAlgorithms(false, PREFERRED_COMPRESSION_ALGORITHMS);
			hashedGen.SetPreferredHashAlgorithms(false, PREFERRED_HASH_ALGORITHMS);
			hashedGen.SetPreferredSymmetricAlgorithms(false, PREFERRED_SYMMETRIC_ALGORITHMS);

			sGen.SetHashedSubpackets(hashedGen.Generate());
			sGen.SetUnhashedSubpackets(unhashedGen.Generate());

			sig = sGen.GenerateCertification(secretDSAKey.PublicKey, secretKey.PublicKey);

			byte[] sigBytes = sig.GetEncoded();

			PgpObjectFactory f = new PgpObjectFactory(sigBytes);

			sig = ((PgpSignatureList) f.NextPgpObject())[0];

			sig.InitVerify(secretDSAKey.PublicKey);

			if (!sig.VerifyCertification(secretDSAKey.PublicKey, secretKey.PublicKey))
			{
				Fail("subkey binding verification failed.");
			}

			PgpSignatureSubpacketVector hashedPcks = sig.GetHashedSubPackets();
			PgpSignatureSubpacketVector unhashedPcks = sig.GetUnhashedSubPackets();

			if (hashedPcks.Count != 6)
			{
				Fail("wrong number of hashed packets found.");
			}

			if (unhashedPcks.Count != 1)
			{
				Fail("wrong number of unhashed packets found.");
			}

			if (!hashedPcks.GetSignerUserId().Equals(TEST_USER_ID))
			{
				Fail("test userid not matching");
			}

			if (hashedPcks.GetSignatureExpirationTime() != TEST_EXPIRATION_TIME)
			{
				Fail("test signature expiration time not matching");
			}

			if (unhashedPcks.GetIssuerKeyId() != secretDSAKey.KeyId)
			{
				Fail("wrong issuer key ID found in certification");
			}

			int[] prefAlgs = hashedPcks.GetPreferredCompressionAlgorithms();
			preferredAlgorithmCheck("compression", PREFERRED_COMPRESSION_ALGORITHMS, prefAlgs);

			prefAlgs = hashedPcks.GetPreferredHashAlgorithms();
			preferredAlgorithmCheck("hash", PREFERRED_HASH_ALGORITHMS, prefAlgs);

			prefAlgs = hashedPcks.GetPreferredSymmetricAlgorithms();
			preferredAlgorithmCheck("symmetric", PREFERRED_SYMMETRIC_ALGORITHMS, prefAlgs);

			SignatureSubpacketTag[] criticalHashed = hashedPcks.GetCriticalTags();

			if (criticalHashed.Length != 1)
			{
				Fail("wrong number of critical packets found.");
			}

			if (criticalHashed[0] != SignatureSubpacketTag.SignerUserId)
			{
				Fail("wrong critical packet found in tag list.");
			}

			//
			// no packets passed
			//
			sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1);

			sGen.InitSign(PgpSignature.SubkeyBinding, pgpPrivDSAKey);

			sGen.SetHashedSubpackets(null);
			sGen.SetUnhashedSubpackets(null);

			sig = sGen.GenerateCertification(TEST_USER_ID, secretKey.PublicKey);

			sig.InitVerify(secretDSAKey.PublicKey);

			if (!sig.VerifyCertification(TEST_USER_ID, secretKey.PublicKey))
			{
				Fail("subkey binding verification failed.");
			}

			hashedPcks = sig.GetHashedSubPackets();

			if (hashedPcks.Count != 1)
			{
				Fail("found wrong number of hashed packets");
			}

			unhashedPcks = sig.GetUnhashedSubPackets();

			if (unhashedPcks.Count != 1)
			{
				Fail("found wrong number of unhashed packets");
			}

			try
			{
				sig.VerifyCertification(secretKey.PublicKey);

				Fail("failed to detect non-key signature.");
			}
			catch (InvalidOperationException)
			{
				// expected
			}

			//
			// override hash packets
			//
			sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1);

			sGen.InitSign(PgpSignature.SubkeyBinding, pgpPrivDSAKey);

			hashedGen = new PgpSignatureSubpacketGenerator();

			DateTime creationTime = new DateTime(1973, 7, 27);
			hashedGen.SetSignatureCreationTime(false, creationTime);

			sGen.SetHashedSubpackets(hashedGen.Generate());

			sGen.SetUnhashedSubpackets(null);

			sig = sGen.GenerateCertification(TEST_USER_ID, secretKey.PublicKey);

			sig.InitVerify(secretDSAKey.PublicKey);

			if (!sig.VerifyCertification(TEST_USER_ID, secretKey.PublicKey))
			{
				Fail("subkey binding verification failed.");
			}

			hashedPcks = sig.GetHashedSubPackets();

			if (hashedPcks.Count != 1)
			{
				Fail("found wrong number of hashed packets in override test");
			}

			if (!hashedPcks.HasSubpacket(SignatureSubpacketTag.CreationTime))
			{
				Fail("hasSubpacket test for creation time failed");
			}

			DateTime sigCreationTime = hashedPcks.GetSignatureCreationTime();
			if (!sigCreationTime.Equals(creationTime))
			{
				Fail("creation of overridden date failed.");
			}

			prefAlgs = hashedPcks.GetPreferredCompressionAlgorithms();
			preferredAlgorithmCheck("compression", NO_PREFERENCES, prefAlgs);

			prefAlgs = hashedPcks.GetPreferredHashAlgorithms();
			preferredAlgorithmCheck("hash", NO_PREFERENCES, prefAlgs);

			prefAlgs = hashedPcks.GetPreferredSymmetricAlgorithms();
			preferredAlgorithmCheck("symmetric", NO_PREFERENCES, prefAlgs);

			if (hashedPcks.GetKeyExpirationTime() != 0)
			{
				Fail("unexpected key expiration time found");
			}

			if (hashedPcks.GetSignatureExpirationTime() != 0)
			{
				Fail("unexpected signature expiration time found");
			}

			if (hashedPcks.GetSignerUserId() != null)
			{
				Fail("unexpected signer user ID found");
			}

			criticalHashed = hashedPcks.GetCriticalTags();

			if (criticalHashed.Length != 0)
			{
				Fail("critical packets found when none expected");
			}

			unhashedPcks = sig.GetUnhashedSubPackets();

			if (unhashedPcks.Count != 1)
			{
				Fail("found wrong number of unhashed packets in override test");
			}

			//
			// general signatures
			//
			doTestSig(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha256, secretKey.PublicKey, pgpPrivKey);
			doTestSig(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha384, secretKey.PublicKey, pgpPrivKey);
			doTestSig(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha512, secretKey.PublicKey, pgpPrivKey);
			doTestSigV3(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);
			doTestTextSig(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
			doTestTextSig(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
			doTestTextSigV3(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
			doTestTextSigV3(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);

			//
			// DSA Tests
			//
			pgpPriv = new PgpSecretKeyRing(dsaKeyRing);
			secretKey = pgpPriv.GetSecretKey();
			pgpPrivKey = secretKey.ExtractPrivateKey(dsaPass);

			try
			{
				doTestSig(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);

				Fail("DSA wrong key test failed.");
			}
			catch (PgpException)
			{
				// expected
			}

			try
			{
				doTestSigV3(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);

				Fail("DSA V3 wrong key test failed.");
			}
			catch (PgpException)
			{
				// expected
			}

			doTestSig(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);
			doTestSigV3(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey);
			doTestTextSig(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
			doTestTextSig(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
			doTestTextSigV3(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
			doTestTextSigV3(PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1, secretKey.PublicKey, pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);

			// special cases
			//
			doTestMissingSubpackets(nullPacketsSubKeyBinding);

			doTestMissingSubpackets(generateV3BinarySig(pgpPrivKey, PublicKeyAlgorithmTag.Dsa, HashAlgorithmTag.Sha1));

			// keyflags
			doTestKeyFlagsValues();
		}

		private void doTestKeyFlagsValues()
		{
			checkValue(KeyFlags.CertifyOther, 0x01);
			checkValue(KeyFlags.SignData, 0x02);
			checkValue(KeyFlags.EncryptComms, 0x04);
			checkValue(KeyFlags.EncryptStorage, 0x08);
			checkValue(KeyFlags.Split, 0x10);
			checkValue(KeyFlags.Authentication, 0x20);
			checkValue(KeyFlags.Shared, 0x80);

			// yes this actually happens
			checkValue(new byte[] { 4, 0, 0, 0 }, 0x04);
			checkValue(new byte[] { 4, 0, 0 }, 0x04);
			checkValue(new byte[] { 4, 0 }, 0x04);
			checkValue(new byte[] { 4 }, 0x04);
		}

		private void checkValue(int flag, int val)
		{
			KeyFlags f = new KeyFlags(true, flag);

			if (f.Flags != val)
			{
				Fail("flag value mismatch");
			}
		}

		private void checkValue(byte[] flag, int val)
		{
			KeyFlags f = new KeyFlags(true, flag);

			if (f.Flags != val)
			{
				Fail("flag value mismatch");
			}
		}

		private void doTestMissingSubpackets(byte[] signature)
		{
			PgpObjectFactory f = new PgpObjectFactory(signature);
			object obj = f.NextPgpObject();

			while (!(obj is PgpSignatureList))
			{
				obj = f.NextPgpObject();
				if (obj is PgpLiteralData)
				{
					Stream input = ((PgpLiteralData)obj).GetDataStream();
					Streams.Drain(input);
				}
			}

			PgpSignature sig = ((PgpSignatureList)obj)[0];

			if (sig.Version > 3)
			{
				PgpSignatureSubpacketVector v = sig.GetHashedSubPackets();

				if (v.GetKeyExpirationTime() != 0)
				{
					Fail("key expiration time not zero for missing subpackets");
				}

				if (!sig.HasSubpackets)
				{
					Fail("HasSubpackets property was false with packets");
				}
			}
			else
			{
				if (sig.GetHashedSubPackets() != null)
				{
					Fail("hashed sub packets found when none expected");
				}

				if (sig.GetUnhashedSubPackets() != null)
				{
					Fail("unhashed sub packets found when none expected");
				}

				if (sig.HasSubpackets)
				{
					Fail("HasSubpackets property was true with no packets");
				}
			}
		}

		private void preferredAlgorithmCheck(
			string	type,
			int[]	expected,
			int[]	prefAlgs)
		{
			if (expected == null)
			{
				if (prefAlgs != null)
				{
					Fail("preferences for " + type + " found when none expected");
				}
			}
			else
			{
				if (prefAlgs.Length != expected.Length)
				{
					Fail("wrong number of preferred " + type + " algorithms found");
				}

				for (int i = 0; i != expected.Length; i++)
				{
					if (expected[i] != prefAlgs[i])
					{
						Fail("wrong algorithm found for " + type + ": expected " + expected[i] + " got " + prefAlgs);
					}
				}
			}
		}

		private void doTestSig(
			PublicKeyAlgorithmTag	encAlgorithm,
			HashAlgorithmTag		hashAlgorithm,
			PgpPublicKey			pubKey,
			PgpPrivateKey			privKey)
		{
			MemoryStream bOut = new MemoryStream();
			MemoryStream testIn = new MemoryStream(TEST_DATA, false);
			PgpSignatureGenerator sGen = new PgpSignatureGenerator(encAlgorithm, hashAlgorithm);

			sGen.InitSign(PgpSignature.BinaryDocument, privKey);
			sGen.GenerateOnePassVersion(false).Encode(bOut);

			PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
			Stream lOut = lGen.Open(
				new UncloseableStream(bOut),
				PgpLiteralData.Binary,
				"_CONSOLE",
				TEST_DATA.Length * 2,
				DateTime.UtcNow);

			int ch;
			while ((ch = testIn.ReadByte()) >= 0)
			{
				lOut.WriteByte((byte)ch);
				sGen.Update((byte)ch);
			}

			lOut.Write(TEST_DATA, 0, TEST_DATA.Length);
			sGen.Update(TEST_DATA);

			lGen.Close();

			sGen.Generate().Encode(bOut);

			verifySignature(bOut.ToArray(), hashAlgorithm, pubKey, TEST_DATA);
		}

		private void doTestTextSig(
			PublicKeyAlgorithmTag	encAlgorithm,
			HashAlgorithmTag		hashAlgorithm,
			PgpPublicKey			pubKey,
			PgpPrivateKey			privKey,
			byte[]					data,
			byte[]					canonicalData)
		{
			PgpSignatureGenerator sGen = new PgpSignatureGenerator(encAlgorithm, HashAlgorithmTag.Sha1);
			MemoryStream bOut = new MemoryStream();
			MemoryStream testIn = new MemoryStream(data, false);
			DateTime creationTime = DateTime.UtcNow;

			sGen.InitSign(PgpSignature.CanonicalTextDocument, privKey);
			sGen.GenerateOnePassVersion(false).Encode(bOut);

			PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
			Stream lOut = lGen.Open(
				new UncloseableStream(bOut),
				PgpLiteralData.Text,
				"_CONSOLE",
				data.Length * 2,
				creationTime);

			int ch;
			while ((ch = testIn.ReadByte()) >= 0)
			{
				lOut.WriteByte((byte)ch);
				sGen.Update((byte)ch);
			}

			lOut.Write(data, 0, data.Length);
			sGen.Update(data);

			lGen.Close();

			PgpSignature sig = sGen.Generate();

			if (sig.CreationTime == DateTimeUtilities.UnixMsToDateTime(0))
			{
				Fail("creation time not set in v4 signature");
			}

			sig.Encode(bOut);

			verifySignature(bOut.ToArray(), hashAlgorithm, pubKey, canonicalData);
		}

		private void doTestSigV3(
			PublicKeyAlgorithmTag	encAlgorithm,
			HashAlgorithmTag		hashAlgorithm,
			PgpPublicKey			pubKey,
			PgpPrivateKey			privKey)
		{
			byte[] bytes = generateV3BinarySig(privKey, encAlgorithm, hashAlgorithm);

			verifySignature(bytes, hashAlgorithm, pubKey, TEST_DATA);
		}

		private byte[] generateV3BinarySig(
			PgpPrivateKey			privKey,
			PublicKeyAlgorithmTag	encAlgorithm,
			HashAlgorithmTag		hashAlgorithm)
		{
			MemoryStream bOut = new MemoryStream();
			MemoryStream testIn = new MemoryStream(TEST_DATA, false);
			PgpV3SignatureGenerator sGen = new PgpV3SignatureGenerator(encAlgorithm, hashAlgorithm);

			sGen.InitSign(PgpSignature.BinaryDocument, privKey);
			sGen.GenerateOnePassVersion(false).Encode(bOut);

			PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
			Stream lOut = lGen.Open(
				new UncloseableStream(bOut),
				PgpLiteralData.Binary,
				"_CONSOLE",
				TEST_DATA.Length * 2,
				DateTime.UtcNow);

			int ch;
			while ((ch = testIn.ReadByte()) >= 0)
			{
				lOut.WriteByte((byte)ch);
				sGen.Update((byte)ch);
			}

			lOut.Write(TEST_DATA, 0, TEST_DATA.Length);
			sGen.Update(TEST_DATA);

			lGen.Close();

			sGen.Generate().Encode(bOut);

			return bOut.ToArray();
		}

		private void doTestTextSigV3(
			PublicKeyAlgorithmTag	encAlgorithm,
			HashAlgorithmTag		hashAlgorithm,
			PgpPublicKey			pubKey,
			PgpPrivateKey			privKey,
			byte[]					data,
			byte[]					canonicalData)
		{
			PgpV3SignatureGenerator sGen = new PgpV3SignatureGenerator(encAlgorithm, HashAlgorithmTag.Sha1);
			MemoryStream bOut = new MemoryStream();
			MemoryStream testIn = new MemoryStream(data, false);

			sGen.InitSign(PgpSignature.CanonicalTextDocument, privKey);
			sGen.GenerateOnePassVersion(false).Encode(bOut);

			PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
			Stream lOut = lGen.Open(
				new UncloseableStream(bOut),
				PgpLiteralData.Text,
				"_CONSOLE",
				data.Length * 2,
				DateTime.UtcNow);

			int ch;
			while ((ch = testIn.ReadByte()) >= 0)
			{
				lOut.WriteByte((byte)ch);
				sGen.Update((byte)ch);
			}

			lOut.Write(data, 0, data.Length);
			sGen.Update(data);

			lGen.Close();

			PgpSignature sig = sGen.Generate();

			if (sig.CreationTime == DateTimeUtilities.UnixMsToDateTime(0))
			{
				Fail("creation time not set in v3 signature");
			}

			sig.Encode(bOut);

			verifySignature(bOut.ToArray(), hashAlgorithm, pubKey, canonicalData);
		}

		private void verifySignature(
			byte[] encodedSig,
			HashAlgorithmTag hashAlgorithm,
			PgpPublicKey pubKey,
			byte[] original)
		{
			PgpObjectFactory        pgpFact = new PgpObjectFactory(encodedSig);
			PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
			PgpOnePassSignature     ops = p1[0];
			PgpLiteralData          p2 = (PgpLiteralData)pgpFact.NextPgpObject();
			Stream					dIn = p2.GetInputStream();

			ops.InitVerify(pubKey);

			int ch;
			while ((ch = dIn.ReadByte()) >= 0)
			{
				ops.Update((byte)ch);
			}

			PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
			PgpSignature sig = p3[0];

			DateTime creationTime = sig.CreationTime;

			// Check creationTime is recent
			if (creationTime.CompareTo(DateTime.UtcNow) > 0
				|| creationTime.CompareTo(DateTime.UtcNow.AddMinutes(-10)) < 0)
			{
				Fail("bad creation time in signature: " + creationTime);
			}

			if (sig.KeyId != pubKey.KeyId)
			{
				Fail("key id mismatch in signature");
			}

			if (!ops.Verify(sig))
			{
				Fail("Failed generated signature check - " + hashAlgorithm);
			}

			sig.InitVerify(pubKey);

			for (int i = 0; i != original.Length; i++)
			{
				sig.Update(original[i]);
			}

			sig.Update(original);

			if (!sig.Verify())
			{
				Fail("Failed generated signature check against original data");
			}
		}

		public override string Name
		{
			get { return "PGPSignatureTest"; }
		}

		public static void Main(
			string[] args)
		{
			RunTest(new PgpSignatureTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
