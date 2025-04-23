using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class CmceVectorTest
    {
        private static readonly Dictionary<string, CmceParameters> Parameters = new Dictionary<string, CmceParameters>()
        {
            { "3488-64-cmce.rsp", CmceParameters.mceliece348864r3 },
            { "3488-64-f-cmce.rsp", CmceParameters.mceliece348864fr3 },
            { "4608-96-cmce.rsp", CmceParameters.mceliece460896r3 },
            { "4608-96-f-cmce.rsp", CmceParameters.mceliece460896fr3 },
            { "6688-128-cmce.rsp", CmceParameters.mceliece6688128r3 },
            { "6688-128-f-cmce.rsp", CmceParameters.mceliece6688128fr3 },
            { "6960-119-cmce.rsp", CmceParameters.mceliece6960119r3 },
            { "6960-119-f-cmce.rsp", CmceParameters.mceliece6960119fr3 },
            { "8192-128-cmce.rsp", CmceParameters.mceliece8192128r3 },
            { "8192-128-f-cmce.rsp", CmceParameters.mceliece8192128fr3 },
        };

        private static readonly string[] TestVectorFiles =
        {
            "3488-64-cmce.rsp",
            "4608-96-cmce.rsp",
            "6688-128-cmce.rsp",
            "6960-119-cmce.rsp",
            "8192-128-cmce.rsp",
        };

        private static readonly string[] TestVectorFilesFast =
        {
            "3488-64-f-cmce.rsp",
            "4608-96-f-cmce.rsp",
            "6688-128-f-cmce.rsp",
            "6960-119-f-cmce.rsp",
            "8192-128-f-cmce.rsp",
        };

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, CmceParameters.mceliece348864r3.DefaultKeySize);
            Assert.AreEqual(128, CmceParameters.mceliece348864fr3.DefaultKeySize);
            Assert.AreEqual(192, CmceParameters.mceliece460896r3.DefaultKeySize);
            Assert.AreEqual(192, CmceParameters.mceliece460896fr3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6688128r3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6688128fr3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6960119r3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6960119fr3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece8192128r3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece8192128fr3.DefaultKeySize);
        }

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        [TestCaseSource(nameof(TestVectorFilesFast))]
        [Parallelizable(ParallelScope.All)]
        public void TVFast(string testVectorFile)
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
            CmceParameters Cmceparameters = Parameters[name];

            CmceKeyPairGenerator kpGen = new CmceKeyPairGenerator();
            CmceKeyGenerationParameters genParam = new CmceKeyGenerationParameters(random, Cmceparameters);
            //
            // Generate keys and test.
            //
            kpGen.Init(genParam);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            CmcePublicKeyParameters pubParams = (CmcePublicKeyParameters)PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((CmcePublicKeyParameters)kp.Public));
            CmcePrivateKeyParameters privParams = (CmcePrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((CmcePrivateKeyParameters)kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetPublicKey()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), name + " " + count + ": secret key");

            // KEM Enc
            CmceKemGenerator CmceEncCipher = new CmceKemGenerator(random);
            ISecretWithEncapsulation secWenc = CmceEncCipher.GenerateEncapsulated(pubParams);
            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), name + " " + count + ": kem_enc key");

            // KEM Dec
            CmceKemExtractor CmceDecCipher = new CmceKemExtractor(privParams);

            byte[] dec_key = CmceDecCipher.ExtractSecret(generated_cipher_text);

            Assert.True(Cmceparameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), name + " " + count + ": kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/cmce", name)))
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
