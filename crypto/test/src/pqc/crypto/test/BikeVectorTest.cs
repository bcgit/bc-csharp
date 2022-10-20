using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class BikeVectorTest
    {
        private static readonly Dictionary<string, BikeParameters> Parameters = new Dictionary<string, BikeParameters>()
        {
            { "PQCkemKAT_BIKE_3114.rsp", BikeParameters.bike128 },
            { "PQCkemKAT_BIKE_6198.rsp", BikeParameters.bike192 },
            { "PQCkemKAT_BIKE_10276.rsp", BikeParameters.bike256 },
        };

        private static readonly string[] TestVectorFiles =
        {
            "PQCkemKAT_BIKE_3114.rsp",
            "PQCkemKAT_BIKE_6198.rsp",
            "PQCkemKAT_BIKE_10276.rsp",
        };

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, BikeParameters.bike128.DefaultKeySize);
            Assert.AreEqual(192, BikeParameters.bike192.DefaultKeySize);
            Assert.AreEqual(256, BikeParameters.bike256.DefaultKeySize);
        }

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        private static void RunTestVector(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]); // seed for SecureRandom
            byte[] pk = Hex.Decode(buf["pk"]);     // public key
            byte[] sk = Hex.Decode(buf["sk"]);     // private key
            byte[] ct = Hex.Decode(buf["ct"]);     // ciphertext
            byte[] ss = Hex.Decode(buf["ss"]);     // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            BikeParameters bikeParameters = Parameters[name];

            BikeKeyPairGenerator kpGen = new BikeKeyPairGenerator();
            BikeKeyGenerationParameters genParam = new BikeKeyGenerationParameters(random, bikeParameters);
            //
            // Generate keys and test.
            //
            kpGen.Init(genParam);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            BikePublicKeyParameters pubParams = (BikePublicKeyParameters)PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((BikePublicKeyParameters) kp.Public));
            BikePrivateKeyParameters privParams = (BikePrivateKeyParameters)PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo((BikePrivateKeyParameters) kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

            // KEM Enc
            BikeKemGenerator BikeEncCipher = new BikeKemGenerator(random);
            ISecretWithEncapsulation secWenc = BikeEncCipher.GenerateEncapsulated(pubParams);
            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");

            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), name + " " + count + ": kem_enc key");

            // KEM Dec
            BikeKemExtractor BikeDecCipher = new BikeKemExtractor(privParams);

            byte[] dec_key = BikeDecCipher.ExtractSecret(generated_cipher_text);

            Assert.True(bikeParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), name + " " + count + ": kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.bike." + name)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf('=');
                        if (a > -1)
                        {
                            buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (buf.Count > 0)
                    {
                        if (!sampler.SkipTest(buf["count"]))
                        {
                            RunTestVector(name, buf);
                        }
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    if (!sampler.SkipTest(buf["count"]))
                    {
                        RunTestVector(name, buf);
                    }
                    buf.Clear();
                }
            }
        }
    }
}
