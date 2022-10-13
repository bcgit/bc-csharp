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
            SaberParameters[] parameters = {
                    SaberParameters.lightsaberkem128r3,
                    SaberParameters.saberkem128r3,
                    SaberParameters.firesaberkem128r3,
                    SaberParameters.lightsaberkem192r3,
                    SaberParameters.saberkem192r3,
                    SaberParameters.firesaberkem192r3,
                    SaberParameters.lightsaberkem256r3,
                    SaberParameters.saberkem256r3,
                    SaberParameters.firesaberkem256r3,
                };

            Assert.AreEqual(128, SaberParameters.lightsaberkem128r3.DefaultKeySize);
            Assert.AreEqual(128, SaberParameters.saberkem128r3.DefaultKeySize);
            Assert.AreEqual(128, SaberParameters.firesaberkem128r3.DefaultKeySize);
            Assert.AreEqual(192, SaberParameters.lightsaberkem192r3.DefaultKeySize);
            Assert.AreEqual(192, SaberParameters.saberkem192r3.DefaultKeySize);
            Assert.AreEqual(192, SaberParameters.firesaberkem192r3.DefaultKeySize);
            Assert.AreEqual(256, SaberParameters.lightsaberkem256r3.DefaultKeySize);
            Assert.AreEqual(256, SaberParameters.saberkem256r3.DefaultKeySize);
            Assert.AreEqual(256, SaberParameters.firesaberkem256r3.DefaultKeySize);
        }

        [Test]
        public void TestVectors()
        {

            SaberParameters[] saberParameters = 
            {
                SaberParameters.lightsaberkem256r3,
                SaberParameters.saberkem256r3,
                SaberParameters.firesaberkem256r3,
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

                            byte[] seed = Hex.Decode(buf["seed"]); // seed for SecureRandom
                            byte[] pk = Hex.Decode(buf["pk"]); // public key
                            byte[] sk = Hex.Decode(buf["sk"]); // private key
                            byte[] ct = Hex.Decode(buf["ct"]); // ciphertext
                            byte[] ss = Hex.Decode(buf["ss"]); // session key

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            SaberParameters parameters = saberParameters[fileIndex];

                            SaberKeyPairGenerator kpGen = new SaberKeyPairGenerator();
                            SaberKeyGenerationParameters
                                genParam = new SaberKeyGenerationParameters(random, parameters);
                            //
                            // Generate keys and test.
                            //
                            kpGen.Init(genParam);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                            SaberPublicKeyParameters pubParams =
                                (SaberPublicKeyParameters) PublicKeyFactory.CreateKey(
                                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                                        (SaberPublicKeyParameters) kp.Public));
                            SaberPrivateKeyParameters privParams =
                                (SaberPrivateKeyParameters) PrivateKeyFactory.CreateKey(
                                    PrivateKeyInfoFactory.CreatePrivateKeyInfo((SaberPrivateKeyParameters) kp.Private));


                            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), name + " " + count + ": public key");
                            Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), name + " " + count + ": secret key");

                            // KEM Enc
                            SaberKemGenerator SABEREncCipher = new SaberKemGenerator(random);
                            ISecretWithEncapsulation secWenc = SABEREncCipher.GenerateEncapsulated(pubParams);
                            byte[] generated_cipher_text = secWenc.GetEncapsulation();
                            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), name + " " + count + ": kem_enc key");

                            // KEM Dec
                            SaberKemExtractor SABERDecCipher = new SaberKemExtractor(privParams);

                            byte[] dec_key = SABERDecCipher.ExtractSecret(generated_cipher_text);

                            Assert.True(parameters.DefaultKeySize == dec_key.Length * 8);
                            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), name + " " + count + ": kem_dec ss");
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