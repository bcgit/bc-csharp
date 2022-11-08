using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.OpenSsl.Tests
{
	[TestFixture]
	public class AllTests
	{
		private class Password
			: IPasswordFinder
		{
			private readonly char[] password;

			public Password(
				char[] word)
			{
				this.password = (char[]) word.Clone();
			}

			public char[] GetPassword()
			{
				return (char[]) password.Clone();
			}
		}

		[Test]
		public void TestPkcs8Encrypted()
		{
			IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
			kpGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));

			AsymmetricKeyParameter privKey = kpGen.GenerateKeyPair().Private;

			// FIXME see PbeUtilities and Pkcs8Generator
//			EncryptedTest(privKey, Pkcs8Generator.Aes256Cbc);
//			EncryptedTest(privKey, Pkcs8Generator.Des3Cbc);
			EncryptedTest(privKey, Pkcs8Generator.PbeSha1_3DES);
		}

		private void EncryptedTest(AsymmetricKeyParameter privKey, string algorithm)
		{
			Pkcs8Generator pkcs8 = new Pkcs8Generator(privKey, algorithm);
			pkcs8.Password = "hello".ToCharArray();

            StringWriter sw = new StringWriter();
			using (var pWrt = new PemWriter(sw))
			{
                pWrt.WriteObject(pkcs8);
            }

			string result = sw.ToString();

			using (var pRd = new PemReader(new StringReader(result), new Password("hello".ToCharArray())))
			{
                AsymmetricKeyParameter rdKey = (AsymmetricKeyParameter)pRd.ReadObject();

                Assert.AreEqual(privKey, rdKey);
            }
        }

		[Test]
		public void TestPkcs8Plain()
		{
			IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
			kpGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));

			AsymmetricKeyParameter privKey = kpGen.GenerateKeyPair().Private;
            Pkcs8Generator pkcs8 = new Pkcs8Generator(privKey);

            StringWriter sw = new StringWriter();
			using (var pWrt = new PemWriter(sw))
			{
                pWrt.WriteObject(pkcs8);
            }

			string result = sw.ToString();

			using (var pRd = new PemReader(new StringReader(result), new Password("hello".ToCharArray())))
			{
                AsymmetricKeyParameter rdKey = (AsymmetricKeyParameter)pRd.ReadObject();

                Assert.AreEqual(privKey, rdKey);
            }
        }
	}
}
