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
        private static readonly Dictionary<string, SaberParameters> Parameters = new Dictionary<string, SaberParameters>()
        {
            { "lightsaber.rsp", SaberParameters.lightsaberkem256r3 },
            { "saber.rsp", SaberParameters.saberkem256r3 },
            { "firesaber.rsp", SaberParameters.firesaberkem256r3 },
            
            { "ulightsaber.rsp", SaberParameters.ulightsaberkemr3},
            { "usaber.rsp", SaberParameters.usaberkemr3},
            { "ufiresaber.rsp", SaberParameters.ufiresaberkemr3},

            { "lightsaber-90s.rsp", SaberParameters.lightsaberkem90sr3},
            { "saber-90s.rsp", SaberParameters.saberkem90sr3},
            { "firesaber-90s.rsp", SaberParameters.firesaberkem90sr3},

            { "ulightsaber-90s.rsp", SaberParameters.ulightsaberkem90sr3},
            { "usaber-90s.rsp", SaberParameters.usaberkem90sr3},
            { "ufiresaber-90s.rsp", SaberParameters.ufiresaberkem90sr3},
        };

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        [Test]
        public void TestParameters()
        {
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
            byte[] pk = Hex.Decode(buf["pk"]); // public key
            byte[] sk = Hex.Decode(buf["sk"]); // private key
            byte[] ct = Hex.Decode(buf["ct"]); // ciphertext
            byte[] ss = Hex.Decode(buf["ss"]); // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SaberParameters parameters = Parameters[name];

            SaberKeyPairGenerator kpGen = new SaberKeyPairGenerator();
            SaberKeyGenerationParameters genParam = new SaberKeyGenerationParameters(random, parameters);
            //
            // Generate keys and test.
            //
            kpGen.Init(genParam);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            SaberPublicKeyParameters pubParams = (SaberPublicKeyParameters)PublicKeyFactory.CreateKey(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((SaberPublicKeyParameters)kp.Public));
            SaberPrivateKeyParameters privParams = (SaberPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo((SaberPrivateKeyParameters)kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetPublicKey()), name + " " + count + ": public key");
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

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.saber." + name)))
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
