using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.OpenSsl.Tests
{
    [TestFixture]
    public class AllTests
    {
        private readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void Pkcs8Encrypted()
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(Random, 1024));

            var kp = kpGen.GenerateKeyPair();
            var privateKey = kp.Private;

            // TODO[Pkcs8Generator]
            //EncryptedTest(privateKey, Pkcs8Generator.Aes128Cbc);
            //EncryptedTest(privateKey, Pkcs8Generator.Aes192Cbc);
            //EncryptedTest(privateKey, Pkcs8Generator.Aes256Cbc);
            //EncryptedTest(privateKey, Pkcs8Generator.Des3Cbc);
            EncryptedTest(privateKey, Pkcs8Generator.PbeWithShaAnd3KeyTripleDesCbc);
        }

        [Test]
        public void Pkcs8Plain()
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(Random, 1024));

            var kp = kpGen.GenerateKeyPair();
            var privateKey = kp.Private;

            Pkcs8Generator pkcs8 = new Pkcs8Generator(privateKey);

            StringWriter sw = new StringWriter();
            using (var pWrt = new PemWriter(sw))
            {
                pWrt.WriteObject(pkcs8);
            }

            string result = sw.ToString();

            using (var pr = new PemReader(new StringReader(result), new TestPassword("hello")))
            {
                AsymmetricKeyParameter readKey = (AsymmetricKeyParameter)pr.ReadObject();

                Assert.AreEqual(privateKey, readKey);
            }
        }

        private void EncryptedTest(AsymmetricKeyParameter privateKey, DerObjectIdentifier algorithm)
        {
            Pkcs8Generator pkcs8 = new Pkcs8Generator(privateKey, algorithm);
            pkcs8.Password = "hello".ToCharArray();

            StringWriter sw = new StringWriter();
            using (var pw = new PemWriter(sw))
            {
                pw.WriteObject(pkcs8);
            }

            string result = sw.ToString();

            using (var pRd = new PemReader(new StringReader(result), new TestPassword("hello")))
            {
                AsymmetricKeyParameter readKey = (AsymmetricKeyParameter)pRd.ReadObject();

                Assert.AreEqual(privateKey, readKey);
            }
        }
    }
}
