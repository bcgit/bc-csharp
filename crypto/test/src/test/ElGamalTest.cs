using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests
{
	[TestFixture]
	public class ElGamalTest
	{
		private static readonly BigInteger G512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
		private static readonly BigInteger P512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

		private static readonly BigInteger G768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
		private static readonly BigInteger P768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

		private static readonly BigInteger G1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
		private static readonly BigInteger P1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

		[Test]
		public void TestGP512()
		{
			DoTestGP(512, 0, G512, P512);
			DoTestGP(512, 64, G512, P512);
		}

		[Test]
		public void TestGP768()
		{
			DoTestGP(768, 0, G768, P768);
			DoTestGP(768, 128, G768, P768);
		}

		[Test]
		public void TestGP1024()
		{
			DoTestGP(1024, 0, G1024, P1024);
			DoTestGP(1024, 256, G1024, P1024);
		}

		[Test]
		public void TestRandom256()
		{
			DoTestRandom(256);
		}

		private void DoTestGP(int size, int privateValueSize, BigInteger g, BigInteger p)
		{
			IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("ElGamal");

			ElGamalParameters elParams = new ElGamalParameters(p, g, privateValueSize);
			ElGamalKeyGenerationParameters elKgp = new ElGamalKeyGenerationParameters(
				new SecureRandom(), elParams);
			keyGen.Init(elKgp);

			AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();
			SecureRandom rand = new SecureRandom();

			CheckKeySize(privateValueSize, keyPair);

			IBufferedCipher cipher = CipherUtilities.GetCipher("ElGamal");

			cipher.Init(true, new ParametersWithRandom(keyPair.Public, rand));

			byte[] inBytes = Encoding.ASCII.GetBytes("This is a test");

			Assert.AreEqual((size / 8) * 2, cipher.GetOutputSize(inBytes.Length), "GetOutputSize wrong on encryption");

			byte[] outBytes = cipher.DoFinal(inBytes);

			cipher.Init(false, keyPair.Private);

			Assert.AreEqual((size / 8) - 1, cipher.GetOutputSize(outBytes.Length), "GetOutputSize wrong on decryption");


			//
			// No Padding - maximum length
			//
			byte[] modBytes = ((ElGamalPublicKeyParameters)keyPair.Public).Parameters.P.ToByteArray();
			byte[] maxInput = new byte[modBytes.Length - 1];

			maxInput[0] |= 0x7f;

			cipher.Init(true, new ParametersWithRandom(keyPair.Public, rand));

			outBytes = cipher.DoFinal(maxInput);

			cipher.Init(false, keyPair.Private);

			outBytes = cipher.DoFinal(outBytes);

			Assert.True(Arrays.AreEqual(outBytes, maxInput), "NoPadding test failed on decrypt expected "
				+ Hex.ToHexString(maxInput) + " got " + Hex.ToHexString(outBytes));


			//
			// encrypt/decrypt
			//
			IBufferedCipher c1 = CipherUtilities.GetCipher("ElGamal");
			IBufferedCipher c2 = CipherUtilities.GetCipher("ElGamal");

			c1.Init(true, new ParametersWithRandom(keyPair.Public, rand));

			byte[] out1 = c1.DoFinal(inBytes);

			c2.Init(false, keyPair.Private);

			byte[] out2 = c2.DoFinal(out1);

			Assert.True(Arrays.AreEqual(inBytes, out2), size + " encrypt test failed");


            //
            // encrypt/decrypt with update
            //
            int outLen = c1.ProcessBytes(inBytes, 0, 2, out1, 0);

            outLen += c1.DoFinal(inBytes, 2, inBytes.Length - 2, out1, outLen);
            Assert.AreEqual(out1.Length, outLen);

            outLen = c2.ProcessBytes(out1, 0, 2, out2, 0);

            outLen += c2.DoFinal(out1, 2, out1.Length - 2, out2, outLen);
            Assert.AreEqual(inBytes.Length, outLen);

            Assert.True(Arrays.AreEqual(inBytes, out2), size + " encrypt with update test failed");



			//
			// public key encoding test
			//
			byte[] pubEnc = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();

			ElGamalPublicKeyParameters pubKey = (ElGamalPublicKeyParameters)
				PublicKeyFactory.CreateKey(pubEnc);
			ElGamalParameters spec = pubKey.Parameters;

			Assert.True(spec.G.Equals(elParams.G) && spec.P.Equals(elParams.P),
				size + " bit public key encoding/decoding test failed on parameters");

			Assert.AreEqual(((ElGamalPublicKeyParameters)keyPair.Public).Y, pubKey.Y,
				size + " bit public key encoding/decoding test failed on y value");


			//
			// private key encoding test
			//
			byte[] privEnc = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded();

			ElGamalPrivateKeyParameters privKey = (ElGamalPrivateKeyParameters)
				PrivateKeyFactory.CreateKey(privEnc);

			spec = privKey.Parameters;

			Assert.True(spec.G.Equals(elParams.G) && spec.P.Equals(elParams.P),
				size + " bit private key encoding/decoding test failed on parameters");

			Assert.AreEqual(((ElGamalPrivateKeyParameters)keyPair.Private).X, privKey.X,
				size + " bit private key encoding/decoding test failed on y value");
		}

		private void CheckKeySize(int privateValueSize, AsymmetricCipherKeyPair aKeyPair)
		{
			if (privateValueSize != 0)
			{
				ElGamalPrivateKeyParameters key = (ElGamalPrivateKeyParameters)aKeyPair.Private;

				Assert.AreEqual(privateValueSize, key.X.BitLength,
					"limited key check failed for key size " + privateValueSize);
			}
		}

		private void DoTestRandom(int size)
		{
			ElGamalParametersGenerator a = new ElGamalParametersGenerator();
			a.Init(size, 20, new SecureRandom());

			ElGamalParameters p = a.GenerateParameters();

			byte[] encodeParams = new ElGamalParameter(p.P, p.G).GetDerEncoded(); 

			ElGamalParameter elP = ElGamalParameter.GetInstance(encodeParams);
			ElGamalParameters p2 = new ElGamalParameters(elP.P, elP.G);

			// a and a2 should be equivalent!
			byte[] encodeParams_2 = new ElGamalParameter(p2.P, p2.G).GetDerEncoded(); 

			Assert.True(Arrays.AreEqual(encodeParams, encodeParams_2), "encode/decode parameters failed");

			DoTestGP(size, 0, elP.G, elP.P);
		}
	}
}
