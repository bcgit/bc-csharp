using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class FrodoVectorTest
    {
        private static readonly Dictionary<string, FrodoParameters> Parameters = new Dictionary<string, FrodoParameters>()
        {
            { "PQCkemKAT_19888.rsp", FrodoParameters.frodokem19888r3 },
            { "PQCkemKAT_31296.rsp", FrodoParameters.frodokem31296r3 },
            { "PQCkemKAT_43088.rsp", FrodoParameters.frodokem43088r3 },
            { "PQCkemKAT_19888_shake.rsp", FrodoParameters.frodokem19888shaker3 },
            { "PQCkemKAT_31296_shake.rsp", FrodoParameters.frodokem31296shaker3 },
            { "PQCkemKAT_43088_shake.rsp", FrodoParameters.frodokem43088shaker3 },
        };

        private static readonly string[] TestVectorFilesAes =
        {
            "PQCkemKAT_19888.rsp",
            "PQCkemKAT_31296.rsp",
            "PQCkemKAT_43088.rsp",
        };

        private static readonly string[] TestVectorFilesShake =
        {
            "PQCkemKAT_19888_shake.rsp",
            "PQCkemKAT_31296_shake.rsp",
            "PQCkemKAT_43088_shake.rsp"
        };

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, FrodoParameters.frodokem19888r3.DefaultKeySize);
            Assert.AreEqual(128, FrodoParameters.frodokem19888shaker3.DefaultKeySize);
            Assert.AreEqual(192, FrodoParameters.frodokem31296r3.DefaultKeySize);
            Assert.AreEqual(192, FrodoParameters.frodokem31296shaker3.DefaultKeySize);
            Assert.AreEqual(256, FrodoParameters.frodokem43088r3.DefaultKeySize);
            Assert.AreEqual(256, FrodoParameters.frodokem43088shaker3.DefaultKeySize);
        }

        [TestCaseSource(nameof(TestVectorFilesAes))]
        [Parallelizable(ParallelScope.All)]
        public void TVAes(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        [TestCaseSource(nameof(TestVectorFilesShake))]
        [Parallelizable(ParallelScope.All)]
        public void TVShake(string testVectorFile)
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
            FrodoParameters frodoParameters = Parameters[name];

            FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
            FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, frodoParameters);
            //
            // Generate keys and test.
            //
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters)kp.Public;
            FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters)kp.Private;

            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), $"{name} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.PrivateKey), $"{name} {count} : secret key");

            // kem_enc
            FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(random);
            ISecretWithEncapsulation secWenc = frodoEncCipher.GenerateEncapsulated(pubParams);
            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc key");

            // kem_dec
            FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParams);

            byte[] dec_key = frodoDecCipher.ExtractSecret(generated_cipher_text);

            Assert.True(frodoParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, ss), $"{name} {count}: kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), $"{name} {count}: kem_dec key");
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.frodo." + name)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf("=");
                        if (a > -1)
                        {
                            buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (buf.Count > 0 && !sampler.SkipTest(buf["count"]))
                    {
                        RunTestVector(name, buf);
                        buf.Clear();
                    }
                }

                if (buf.Count > 0 && !sampler.SkipTest(buf["count"]))
                {
                    RunTestVector(name, buf);
                }
            }
        }
    }
}
