using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pkcs.Tests
{
    [TestFixture]
    public class EncryptedPrivateKeyInfoTest
    {
        [Test]
        public void Basic()
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

            EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc.Id, password1, salt, iterationCount,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private));

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password1, encInfo);

            AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(info);

            Assert.AreEqual(key, pair.Private, "Key corrupted");
        }

        [Test]
        public void Pbkdf2IterationCountBound()
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

            Properties.WithThreadProperty(Properties.PbeMaxIterationCount, "1", () =>
            {
                try
                {
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(password, encInfo);
                    Assert.Fail("excessive PBKDF2 iteration count accepted");
                }
                catch (ArgumentException e)
                {
                    Assert.That(e.Message.IndexOf("greater than 1") >= 0, "unexpected message: " + e.Message);
                }
            });
        }

        [Test]
        public void Pkcs5V1PbeIterationCountBound()
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

            Properties.WithThreadProperty(Properties.PbeMaxIterationCount, "1", () =>
            {
                try
                {
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(password, encInfo);
                    Assert.Fail("excessive PKCS#5 v1.5 PBE iteration count accepted");
                }
                catch (ArgumentException e)
                {
                    Assert.That(e.Message.IndexOf("greater than 1") >= 0, "unexpected message: " + e.Message);
                }
            });
        }

        [Test]
        public void OpensslTestKeys()
        {
            string[] names = SimpleTest.GetTestDataEntries("keys");
            foreach (string name in names)
            {
                if (!name.EndsWith(".key"))
                    continue;

                Stream data = SimpleTest.GetTestDataAsStream(name);
                AsymmetricKeyParameter key = PrivateKeyFactory.DecryptKey("12345678a".ToCharArray(), data);

                Assert.True(key is RsaPrivateCrtKeyParameters, "Sample key could not be decrypted: " + name);
            }
        }
    }
}
