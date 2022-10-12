using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using NUnit.Framework;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Pqc.Crypto.Bike;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class BikeVectorTest
    {
        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, BikeParameters.bike128.DefaultKeySize);
            Assert.AreEqual(192, BikeParameters.bike192.DefaultKeySize);
            Assert.AreEqual(256, BikeParameters.bike256.DefaultKeySize);
        }
        
        [Test]
        public void TestVectors()
        {
            bool full = false;
            
            string[] files;
            if (full)
            {
                files = new []{
                    "PQCkemKAT_BIKE_3114.rsp",
                    "PQCkemKAT_BIKE_6198.rsp",
                    "PQCkemKAT_BIKE_10276.rsp"
                };
            }
            else
            {
                files = new []{
                    "PQCkemKAT_BIKE_3114.rsp"
                };
            }

            BikeParameters[] parameters = {
                    BikeParameters.bike128,
                    BikeParameters.bike192,
                    BikeParameters.bike256
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                string name = files[fileIndex];
                Console.Write($"testing: {name}");
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.bike." + name));

                string line = null;
                Dictionary<string, string> buf = new Dictionary<string, string>();
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();

                    if (line.StartsWith("#"))
                    {
                        continue;
                    }
                    if (line.Length == 0)
                    {
                        if (buf.Count > 0 && !sampler.SkipTest(buf["count"]))
                        {
                            string count = buf["count"];

                            Console.Write($"test case: {count}\n");
                            byte[] seed = Hex.Decode(buf["seed"]); // seed for Cmce secure random
                            byte[] pk = Hex.Decode(buf["pk"]);     // public key
                            byte[] sk = Hex.Decode(buf["sk"]);     // private key
                            byte[] ct = Hex.Decode(buf["ct"]);     // ciphertext
                            byte[] ss = Hex.Decode(buf["ss"]);     // session key

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            BikeParameters bikeParameters = parameters[fileIndex];

                            BikeKeyPairGenerator kpGen = new BikeKeyPairGenerator();
                            BikeKeyGenerationParameters genParam = new BikeKeyGenerationParameters(random, bikeParameters);
                            //
                            // Generate keys and test.
                            //
                            kpGen.Init(genParam);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                            BikePublicKeyParameters pubParams = (BikePublicKeyParameters)PublicKeyFactory.CreateKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((BikePublicKeyParameters) kp.Public));
                            BikePrivateKeyParameters privParams = (BikePrivateKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo((BikePrivateKeyParameters) kp.Private));

                            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), name + " " + count + ": public key");
                            Assert.True(Arrays.AreEqual(sk, privParams.PrivateKey), name + " " + count + ": secret key");

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
                        buf.Clear();

                        continue;
                    }

                    int a = line.IndexOf('=');
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