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
        [Test]
        public void TestParameters()
        {
            FrodoParameters[] parameters = {
                FrodoParameters.frodokem19888r3,
                FrodoParameters.frodokem19888shaker3,
                FrodoParameters.frodokem31296r3,
                FrodoParameters.frodokem31296shaker3,
                FrodoParameters.frodokem43088r3,
                FrodoParameters.frodokem43088shaker3
            };

            Assert.AreEqual(128, FrodoParameters.frodokem19888r3.DefaultKeySize);
            Assert.AreEqual(128, FrodoParameters.frodokem19888shaker3.DefaultKeySize);
            Assert.AreEqual(192, FrodoParameters.frodokem31296r3.DefaultKeySize);
            Assert.AreEqual(192, FrodoParameters.frodokem31296shaker3.DefaultKeySize);
            Assert.AreEqual(256, FrodoParameters.frodokem43088r3.DefaultKeySize);
            Assert.AreEqual(256, FrodoParameters.frodokem43088shaker3.DefaultKeySize);
        }
        
        [Test]
        public void TestVectors()
        {
            string[] files = {
                "PQCkemKAT_19888.rsp",
                "PQCkemKAT_31296.rsp",
                "PQCkemKAT_43088.rsp",
                "PQCkemKAT_19888_shake.rsp",
                "PQCkemKAT_31296_shake.rsp",
                "PQCkemKAT_43088_shake.rsp"
            };

            FrodoParameters[] parameters = {
                FrodoParameters.frodokem19888r3,
                FrodoParameters.frodokem31296r3,
                FrodoParameters.frodokem43088r3,
                FrodoParameters.frodokem19888shaker3,
                FrodoParameters.frodokem31296shaker3,
                FrodoParameters.frodokem43088shaker3
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                String name = files[fileIndex];
                Console.Write($"testing: {name}\n");
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.frodo." + name));

                String line = null;
                Dictionary<String, String> buf = new Dictionary<string, string>();
                // Random rnd = new Random(System.currentTimeMillis());
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();

                    if (line.StartsWith("#"))
                    {
                        continue;
                    }
                    if (line.Length == 0)
                    {
                        if (buf.Count > 0)
                        {
                            string count = buf["count"];
                            if (sampler.SkipTest(count))
                                continue;

                            Console.Write($"test case: {count}");

                            byte[] seed = Hex.Decode(buf["seed"]); // seed for nist secure random
                            byte[] pk = Hex.Decode(buf["pk"]);     // public key
                            byte[] sk = Hex.Decode(buf["sk"]);     // private key
                            byte[] ct = Hex.Decode(buf["ct"]);     // ciphertext
                            byte[] ss = Hex.Decode(buf["ss"]);     // session key

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            FrodoParameters frodoParameters = parameters[fileIndex];

                            FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
                            FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, frodoParameters);
                            //
                            // Generate keys and test.
                            //
                            kpGen.Init(genParams);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                            FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters) kp.Public;
                            FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters) kp.Private;

                            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), $"{name} {count} : public key");
                            Assert.True( Arrays.AreEqual(sk, privParams.PrivateKey),$"{name} {count} : secret key");

                            // kem_enc
                            FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(random);
                            ISecretWithEncapsulation secWenc = frodoEncCipher.GenerateEncapsulated(pubParams);
                            byte[] generated_cipher_text = secWenc.GetEncapsulation();
                            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
                            byte[] secret = secWenc.GetSecret();
                            Assert.True( Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc key");

                            // kem_dec
                            FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParams);

                            byte[] dec_key = frodoDecCipher.ExtractSecret(generated_cipher_text);

                            Assert.True(frodoParameters.DefaultKeySize == dec_key.Length * 8);
                            Assert.True(Arrays.AreEqual(dec_key, ss), $"{name} {count}: kem_dec ss");
                            Assert.True(Arrays.AreEqual(dec_key, secret),$"{name} {count}: kem_dec key");
                        }
                        buf.Clear();

                        continue;
                    }

                    int a = line.IndexOf("=");
                    if (a > -1)
                    {
                        buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }
                }
                Console.Write("testing successful!");
            }
        }
    }
}