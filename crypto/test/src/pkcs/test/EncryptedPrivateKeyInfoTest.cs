using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pkcs.Tests
{
    [TestFixture]
    [NonParallelizable] // Environment.SetEnvironmentVariable
    public class EncryptedPrivateKeyInfoTest
        : SimpleTest
    {
        private readonly string alg = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc.Id; // 3 key triple DES with SHA-1

		public override string Name
        {
			get { return "EncryptedPrivateKeyInfoTest"; }
        }

		public override void PerformTest()
        {
            IAsymmetricCipherKeyPairGenerator pGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            RsaKeyGenerationParameters genParam = new RsaKeyGenerationParameters(
				BigInteger.ValueOf(0x10001), new SecureRandom(), 512, 25);

			pGen.Init(genParam);

			AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();

            //
            // set up the parameters
            //
            byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            int iterationCount = 100;

			//
            // set up the key
            //
            char[] password1 = { 'h', 'e', 'l', 'l', 'o' };

            EncryptedPrivateKeyInfo  encInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(alg, password1, salt, iterationCount, PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private));

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password1, encInfo);

            AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(info);

            if (!key.Equals(pair.Private))
            {
                Fail("Key corrupted");
            }

			doOpensslTestKeys();

			ImplTestPbkdf2IterationCountBound();
			ImplTestPkcs5V1PbeIterationCountBound();
		}

		private void ImplTestPbkdf2IterationCountBound()
		{
			IAsymmetricCipherKeyPairGenerator pGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
			pGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 512, 25));
			AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();
			PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private);

			char[] password = { 'h', 'e', 'l', 'l', 'o' };
			byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
			int iterationCount = 2048;

			// The PBES2/PBKDF2 iteration count travels in the unauthenticated encrypted-key container,
			// so it must be bounded before the key-derivation runs. Encrypt with a normal count, then
			// decrypt with the bound lowered below it: decryption must be rejected before the derivation.
			EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
				NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256, password, salt,
				iterationCount, new SecureRandom(), pkInfo);

			const string maxIterationCountProperty = "Org.BouncyCastle.Pbe.MaxIterationCount";
			string savedMax = Environment.GetEnvironmentVariable(maxIterationCountProperty);
			Environment.SetEnvironmentVariable(maxIterationCountProperty, "1");
			try
			{
				PrivateKeyInfoFactory.CreatePrivateKeyInfo(password, encInfo);
				Fail("excessive PBKDF2 iteration count accepted");
			}
			catch (ArgumentException e)
			{
				IsTrue("unexpected message: " + e.Message, e.Message.IndexOf("greater than 1") >= 0);
			}
			finally
			{
				Environment.SetEnvironmentVariable(maxIterationCountProperty, savedMax);
			}
		}

		private void ImplTestPkcs5V1PbeIterationCountBound()
		{
			IAsymmetricCipherKeyPairGenerator pGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
			pGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 512, 25));
			PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pGen.GenerateKeyPair().Private);

			char[] password = { 'h', 'e', 'l', 'l', 'o' };
			byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };

			// The PKCS#5 v1.5 PBE iteration count (sibling of the PBES2 path) is likewise read from the
			// unauthenticated PKCS#8 container and must be bounded before the key derivation runs.
			EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
				PkcsObjectIdentifiers.PbeWithSha1AndDesCbc.Id, password, salt, 2048, pkInfo);

			const string maxIterationCountProperty = "Org.BouncyCastle.Pbe.MaxIterationCount";
			string savedMax = Environment.GetEnvironmentVariable(maxIterationCountProperty);
			Environment.SetEnvironmentVariable(maxIterationCountProperty, "1");
			try
			{
				PrivateKeyInfoFactory.CreatePrivateKeyInfo(password, encInfo);
				Fail("excessive PKCS#5 v1.5 PBE iteration count accepted");
			}
			catch (ArgumentException e)
			{
				IsTrue("unexpected message: " + e.Message, e.Message.IndexOf("greater than 1") >= 0);
			}
			finally
			{
				Environment.SetEnvironmentVariable(maxIterationCountProperty, savedMax);
			}
		}

        private void doOpensslTestKeys()
		{
			string[] names = GetTestDataEntries("keys");
			foreach (string name in names)
			{
                if (!name.EndsWith(".key"))
                    continue;

//				Console.Write(name + " => ");
				Stream data = GetTestDataAsStream(name);
				AsymmetricKeyParameter key = PrivateKeyFactory.DecryptKey("12345678a".ToCharArray(), data);
//				Console.WriteLine(key.GetType().Name);
				if (!(key is RsaPrivateCrtKeyParameters))
				{
					Fail("Sample key could not be decrypted: " + name);
				}
			}
		}

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
