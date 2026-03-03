using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.OpenSsl.Tests
{
    /**
    * basic class for reading test.pem - the password is "secret"
    */
    [TestFixture]
    public class ReaderTest
        : SimpleTest
    {
        private readonly SecureRandom Random = new SecureRandom();

        public override string Name => "ReaderTest";

        [Test]
        public void TestGost3410_2012()
        {
            string data =
                "-----BEGIN PRIVATE KEY-----" +
                "MEMCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIIBidanaO5G6Go8A" +
                "thlDjR9rk4hij/PpjAQvXJr+zTqz" +
                "-----END PRIVATE KEY-----";

            using (var textReader = new StringReader(data))
            using (var pemReader = new PemReader(textReader))
            {
                var pemObj = pemReader.ReadPemObject();
                PrivateKeyFactory.CreateKey(pemObj.Content);
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        public override void PerformTest()
        {
            IPasswordFinder pGet = new TestPassword("secret");
            using (var pemRd = OpenPemResource("test.pem", pGet))
            {
                object o;
                while ((o = pemRd.ReadObject()) != null)
                {
                    //if (o is AsymmetricCipherKeyPair)
                    //{
                    //    ackp = (AsymmetricCipherKeyPair)o;

                    //    Console.WriteLine(ackp.Public);
                    //    Console.WriteLine(ackp.Private);
                    //}
                    //else
                    //{
                    //    Console.WriteLine(o.ToString());
                    //}
                }
            }

            //
            // pkcs 7 data
            //
            ContentInfo d;
            using (var pemRd = OpenPemResource("pkcs7.pem", null))
            {
                d = (ContentInfo)pemRd.ReadObject();

                if (!d.ContentType.Equals(CmsObjectIdentifiers.EnvelopedData))
                {
                    Fail("failed envelopedData check");
                }
            }

            /*
            {
                //
                // ECKey
                //
                pemRd = OpenPemResource("eckey.pem", null);
    
                // TODO Resolve return type issue with EC keys and fix PemReader to return parameters
                //ECNamedCurveParameterSpec spec = (ECNamedCurveParameterSpec)pemRd.ReadObject();
    
                pair = (AsymmetricCipherKeyPair)pemRd.ReadObject();
                ISigner sgr = SignerUtilities.GetSigner("ECDSA");
    
                sgr.Init(true, pair.Private);
    
                byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
    
                sgr.BlockUpdate(message, 0, message.Length);
    
                byte[] sigBytes = sgr.GenerateSignature();
    
                sgr.Init(false, pair.Public);
    
                sgr.BlockUpdate(message, 0, message.Length);
    
                if (!sgr.VerifySignature(sigBytes))
                {
                    Fail("EC verification failed");
                }

                // TODO Resolve this issue with the algorithm name, study Java version
                //if (!((ECPublicKeyParameters) pair.Public).AlgorithmName.Equals("ECDSA"))
                //{
                //    Fail("wrong algorithm name on public got: " + ((ECPublicKeyParameters) pair.Public).AlgorithmName);
                //}
                
                //if (!((ECPrivateKeyParameters) pair.Private).AlgorithmName.Equals("ECDSA"))
                //{
                //    Fail("wrong algorithm name on private got: " + ((ECPrivateKeyParameters) pair.Private).AlgorithmName);
                //}
            }
            */

            //
            // writer/parser test
            //
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 768, 25));

            var kp = kpGen.GenerateKeyPair();

            ImplKeyPairTest("RSA", kp);

            //kpGen = KeyPairGenerator.getInstance("DSA");
            //kpGen.initialize(512, Random);
            DsaParametersGenerator pGen = new DsaParametersGenerator();
            pGen.Init(512, 80, Random);

            kpGen = GeneratorUtilities.GetKeyPairGenerator("DSA");
            kpGen.Init(new DsaKeyGenerationParameters(Random, pGen.GenerateParameters()));

            kp = kpGen.GenerateKeyPair();

            ImplKeyPairTest("DSA", kp);

            //
            // PKCS7
            //
            MemoryStream bOut = new MemoryStream();
            using (var pWrt = new PemWriter(new StreamWriter(bOut)))
            {
                pWrt.WriteObject(d);
            }

            using (var pemRd = new PemReader(new StreamReader(new MemoryStream(bOut.ToArray(), false))))
            {
                d = (ContentInfo)pemRd.ReadObject();

                if (!CmsObjectIdentifiers.EnvelopedData.Equals(d.ContentType))
                {
                    Fail("failed EnvelopedData recode check");
                }
            }

            // OpenSSL test cases (as embedded resources)
            ImplOpenSslDsaTest("unencrypted");
            ImplOpenSslRsaTest("unencrypted");

            ImplOpenSslTests("aes128");
            ImplOpenSslTests("aes192");
            ImplOpenSslTests("aes256");
            ImplOpenSslTests("blowfish");
            ImplOpenSslTests("des1");
            ImplOpenSslTests("des2");
            ImplOpenSslTests("des3");
            ImplOpenSslTests("rc2_128");

            ImplOpenSslDsaTest("rc2_40_cbc");
            ImplOpenSslRsaTest("rc2_40_cbc");
            ImplOpenSslDsaTest("rc2_64_cbc");
            ImplOpenSslRsaTest("rc2_64_cbc");

            ImplDudPasswordTest("7fd98", 0, "corrupted stream - out of bounds length found: 599005160 >= 19");
            ImplDudPasswordTest("ef677", 1, "corrupted stream - out of bounds length found: 2087569732 >= 66");
            ImplDudPasswordTest("800ce", 2, "unknown tag 26 encountered");
            ImplDudPasswordTest("b6cd8", 3, "DEF length 81 object truncated by 56");
            ImplDudPasswordTest("28ce09", 4, "corrupted stream - high tag number < 31 found");
            ImplDudPasswordTest("2ac3b9", 5, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("2cba96", 6, "corrupted stream - out of bounds length found: 100 >= 67");
            ImplDudPasswordTest("2e3354", 7, "corrupted stream - out of bounds length found: 42 >= 35");
            ImplDudPasswordTest("2f4142", 8, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("2fe9bb", 9, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("3ee7a8", 10, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("41af75", 11, "unknown tag 16 encountered");
            ImplDudPasswordTest("1704a5", 12, "corrupted stream detected");
            ImplDudPasswordTest("1c5822", 13, "extra data found after object");
            ImplDudPasswordTest("5a3d16", 14, "corrupted stream detected");
            ImplDudPasswordTest("8d0c97", 15, "corrupted stream detected");
            ImplDudPasswordTest("bc0daf", 16, "corrupted stream detected");
            ImplDudPasswordTest("aaf9c4d", 17, "corrupted stream - out of bounds length found: 1580418590 >= 447");

            // encrypted private key test
            pGet = new TestPassword("password");
            using (var pemRd = OpenPemResource("enckey.pem", pGet))
            {
                var privKey = (RsaPrivateCrtKeyParameters)pemRd.ReadObject();

                if (!privKey.PublicExponent.Equals(new BigInteger("10001", 16)))
                {
                    Fail("decryption of private key data check failed");
                }
            }

            // general PKCS8 test
            pGet = new TestPassword("password");
            using (var pemRd = OpenPemResource("pkcs8test.pem", pGet))
            {
                RsaPrivateCrtKeyParameters privKey;
                while ((privKey = (RsaPrivateCrtKeyParameters)pemRd.ReadObject()) != null)
                {
                    if (!privKey.PublicExponent.Equals(new BigInteger("10001", 16)))
                    {
                        Fail("decryption of private key data check failed");
                    }
                }
            }
        }

        private void ImplKeyPairTest(string name, AsymmetricCipherKeyPair pair)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pWrt = new PemWriter(new StreamWriter(bOut)))
            {
                pWrt.WriteObject(pair.Public);
            }

            using (var pemRd = new PemReader(new StreamReader(new MemoryStream(bOut.ToArray(), false))))
            {
                AsymmetricKeyParameter pubK = (AsymmetricKeyParameter)pemRd.ReadObject();
                if (!pubK.Equals(pair.Public))
                {
                    Fail("Failed public key read: " + name);
                }
            }

            bOut = new MemoryStream();
            using (var pWrt = new PemWriter(new StreamWriter(bOut)))
            {
                pWrt.WriteObject(pair.Private);
            }

            using (var pemRd = new PemReader(new StreamReader(new MemoryStream(bOut.ToArray(), false))))
            {
                AsymmetricCipherKeyPair kPair = (AsymmetricCipherKeyPair)pemRd.ReadObject();
                if (!kPair.Private.Equals(pair.Private))
                {
                    Fail("Failed private key read: " + name);
                }
                if (!kPair.Public.Equals(pair.Public))
                {
                    Fail("Failed private key public read: " + name);
                }
            }
        }

        private void ImplOpenSslTests(string baseName)
        {
            ImplOpenSslDsaModesTest(baseName);
            ImplOpenSslRsaModesTest(baseName);
        }

        private void ImplOpenSslDsaModesTest(string baseName)
        {
            ImplOpenSslDsaTest(baseName + "_cbc");
            ImplOpenSslDsaTest(baseName + "_cfb");
            ImplOpenSslDsaTest(baseName + "_ecb");
            ImplOpenSslDsaTest(baseName + "_ofb");
        }

        private void ImplOpenSslRsaModesTest(string baseName)
        {
            ImplOpenSslRsaTest(baseName + "_cbc");
            ImplOpenSslRsaTest(baseName + "_cfb");
            ImplOpenSslRsaTest(baseName + "_ecb");
            ImplOpenSslRsaTest(baseName + "_ofb");
        }

        private void ImplOpenSslDsaTest(string name)
        {
            string fileName = "dsa.openssl_dsa_" + name + ".pem";

            ImplOpenSslTestFile(fileName, typeof(DsaPrivateKeyParameters));
        }

        private void ImplOpenSslRsaTest(string name)
        {
            string fileName = "rsa.openssl_rsa_" + name + ".pem";

            ImplOpenSslTestFile(fileName, typeof(RsaPrivateCrtKeyParameters));
        }

        private void ImplOpenSslTestFile(string fileName, Type expectedPrivKeyType)
        {
            using (var pr = OpenPemResource(fileName, new TestPassword("changeit")))
            {
                AsymmetricCipherKeyPair kp = pr.ReadObject() as AsymmetricCipherKeyPair;

                if (kp == null)
                {
                    Fail("Didn't find OpenSSL key");
                }

                if (!expectedPrivKeyType.IsInstanceOfType(kp.Private))
                {
                    Fail("Returned key not of correct type");
                }
            }
        }

        private void ImplDudPasswordTest(string password, int index, string message)
        {
            // illegal state exception check - in this case the wrong password will
            // cause an underlying class cast exception.
            try
            {
                IPasswordFinder pGet = new TestPassword(password);
                using (var pemRd = OpenPemResource("test.pem", pGet))
                {
                    object o;
                    while ((o = pemRd.ReadObject()) != null)
                    {
                    }
                }
                Fail("issue not detected: " + index);
            }
            catch (Exception e)
            {
                if (e.Message.IndexOf(message) < 0)
                {
                    Console.Error.WriteLine(message);
                    Console.Error.WriteLine(e.Message);
                    Fail("issue " + index + " exception thrown, but wrong message");
                }
            }
        }

        private static PemReader OpenPemResource(string fileName, IPasswordFinder pGet)
        {
            Stream data = GetTestDataAsStream("openssl." + fileName);
            TextReader tr = new StreamReader(data);
            return new PemReader(tr, pGet);
        }
    }
}
