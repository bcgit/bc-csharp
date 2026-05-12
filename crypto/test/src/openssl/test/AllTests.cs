using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

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

        /**
         * github #400: OpenSSL 1.1+ "openssl pkcs8 -topk8 -scrypt" emits a PBES2
         * EncryptedPrivateKeyInfo whose key-derivation function is scrypt
         * (RFC 7914) rather than PBKDF2. JceOpenSSLPKCS8DecryptorProviderBuilder
         * previously cast the KDF parameters blind to PBKDF2Params and threw
         * "DLSequence cannot be cast to PBKDF2Params". The builder now recognises
         * id-scrypt inside PBES2 and derives the key via SCrypt.generate.
         *
         * Fixture from RFC 7914 sec. 7.2 (password "Rabbit").
         */
        [Test, Ignore("incomplete")]
        public void ScryptOpenSSLDecryptorIssue400()
        {
            byte[] pkcs8Scrypt = Base64.Decode(
                "MIHiME0GCSqGSIb3DQEFDTBAMB8GCSsGAQQB2kcECzASBAVNb3VzZQIDEAAAAgEI" +
                "AgEBMB0GCWCGSAFlAwQBKgQQyYmguHMsOwzGMPoyObk/JgSBkJb47EWd5iAqJlyy" +
                "+ni5ftd6gZgOPaLQClL7mEZc2KQay0VhjZm/7MbBUNbqOAXNM6OGebXxVp6sHUAL" +
                "iBGY/Dls7B1TsWeGObE0sS1MXEpuREuloZjcsNVcNXWPlLdZtkSH6uwWzR0PyG/Z" +
                "+ZXfNodZtd/voKlvLOw5B3opGIFaLkbtLZQwMiGtl42AS89lZg==");

            byte[] expected = Base64.Decode(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4RaNK5CuHY3CXr9f" +
                "/CdVgOhEurMohrQmWbbLZK4ZInyhRANCAARs2WMV6UMlLjLaoc0Dsdnj4Vlffc9T" +
                "t48lJU0RiCzXc280Vg/H5fm1xAP1B7UnIVcBqgDHDcfqWm1h/xSeCHXS");

            Pkcs8EncryptedPrivateKeyInfo info = new Pkcs8EncryptedPrivateKeyInfo(pkcs8Scrypt);

            //PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo(
            //    new JceOpenSSLPKCS8DecryptorProviderBuilder()
            //        .setProvider("BC")
            //        .build("Rabbit".toCharArray()));
            IDecryptorBuilderProvider inputDecryptorProvider = null;
            PrivateKeyInfo pkInfo = info.DecryptPrivateKeyInfo(inputDecryptorProvider);

            Assert.True(Arrays.AreEqual(expected, pkInfo.GetEncoded()));
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
