using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class SaberVectorTest
    {
        [Test]
        public void TestParamaters()
        {
            SABERParameters[] parameters = {
                    SABERParameters.lightsaberkem128r3,
                    SABERParameters.saberkem128r3,
                    SABERParameters.firesaberkem128r3,
                    SABERParameters.lightsaberkem192r3,
                    SABERParameters.saberkem192r3,
                    SABERParameters.firesaberkem192r3,
                    SABERParameters.lightsaberkem256r3,
                    SABERParameters.saberkem256r3,
                    SABERParameters.firesaberkem256r3,
                };

            Assert.AreEqual(128, SABERParameters.lightsaberkem128r3.GetDefaultKeySize());
            Assert.AreEqual(128, SABERParameters.saberkem128r3.GetDefaultKeySize());
            Assert.AreEqual(128, SABERParameters.firesaberkem128r3.GetDefaultKeySize());
            Assert.AreEqual(192, SABERParameters.lightsaberkem192r3.GetDefaultKeySize());
            Assert.AreEqual(192, SABERParameters.saberkem192r3.GetDefaultKeySize());
            Assert.AreEqual(192, SABERParameters.firesaberkem192r3.GetDefaultKeySize());
            Assert.AreEqual(256, SABERParameters.lightsaberkem256r3.GetDefaultKeySize());
            Assert.AreEqual(256, SABERParameters.saberkem256r3.GetDefaultKeySize());
            Assert.AreEqual(256, SABERParameters.firesaberkem256r3.GetDefaultKeySize());
        }

        [Test]
        public void TestVectors()
        {

            SABERParameters[] saberParameters = 
            {
                SABERParameters.lightsaberkem256r3,
                SABERParameters.saberkem256r3,
                SABERParameters.firesaberkem256r3,
            };
            String[] files = 
            {
                "lightsaber.rsp",
                "saber.rsp",
                "firesaber.rsp"
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                String name = files[fileIndex];
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.saber." + name));


                String line = null;
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
                            String count = buf["count"];

                            byte[] seed = Hex.Decode(buf["seed"]); // seed for SABER secure random
                            byte[] pk = Hex.Decode(buf["pk"]); // public key
                            byte[] sk = Hex.Decode(buf["sk"]); // private key
                            byte[] ct = Hex.Decode(buf["ct"]); // ciphertext
                            byte[] ss = Hex.Decode(buf["ss"]); // session key

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            SABERParameters parameters = saberParameters[fileIndex];

                            SABERKeyPairGenerator kpGen = new SABERKeyPairGenerator();
                            SABERKeyGenerationParameters
                                genParam = new SABERKeyGenerationParameters(random, parameters);
                            //
                            // Generate keys and test.
                            //
                            kpGen.Init(genParam);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                            SABERPublicKeyParameters pubParams =
                                (SABERPublicKeyParameters) PublicKeyFactory.CreateKey(
                                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                                        (SABERPublicKeyParameters) kp.Public));
                            SABERPrivateKeyParameters privParams =
                                (SABERPrivateKeyParameters) PrivateKeyFactory.CreateKey(
                                    PrivateKeyInfoFactory.CreatePrivateKeyInfo((SABERPrivateKeyParameters) kp.Private));


                            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), name + " " + count + ": public key");
                            Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), name + " " + count + ": secret key");

                            // KEM Enc
                            SABERKEMGenerator SABEREncCipher = new SABERKEMGenerator(random);
                            ISecretWithEncapsulation secWenc = SABEREncCipher.GenerateEncapsulated(pubParams);
                            byte[] generated_cipher_text = secWenc.GetEncapsulation();
                            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc key");

                            // KEM Dec
                            SABERKEMExtractor SABERDecCipher = new SABERKEMExtractor(privParams);

                            byte[] dec_key = SABERDecCipher.ExtractSecret(generated_cipher_text);

                            Assert.True(Arrays.AreEqual(dec_key, ss), name + " " + count + ": kem_dec ss");
                            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
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
            }
        }
    }
}