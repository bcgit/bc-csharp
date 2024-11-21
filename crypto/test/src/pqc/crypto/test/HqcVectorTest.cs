using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class HqcVectorTest
    {
        private static readonly Dictionary<string, HqcParameters> Parameters = new Dictionary<string, HqcParameters>()
        {
            { "hqc-128_kat.rsp", HqcParameters.hqc128 },
            { "hqc-192_kat.rsp", HqcParameters.hqc192 },
            { "hqc-256_kat.rsp", HqcParameters.hqc256 },
        };

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, HqcParameters.hqc128.DefaultKeySize);
            Assert.AreEqual(192, HqcParameters.hqc192.DefaultKeySize);
            Assert.AreEqual(256, HqcParameters.hqc256.DefaultKeySize);
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

            //NistSecureRandom random = new NistSecureRandom(seed, null);
            FixedSecureRandom random = new FixedSecureRandom(
                new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(seed) });
            HqcParameters hqcParameters = Parameters[name];

            HqcKeyPairGenerator kpGen = new HqcKeyPairGenerator();
            HqcKeyGenerationParameters genParam = new HqcKeyGenerationParameters(random, hqcParameters);

            //
            // Generate keys and test.
            //
            kpGen.Init(genParam);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HqcPublicKeyParameters pubParams = (HqcPublicKeyParameters)PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((HqcPublicKeyParameters) kp.Public));
            HqcPrivateKeyParameters privParams = (HqcPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((HqcPrivateKeyParameters) kp.Private));
                           
            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.PrivateKey), name + " " + count + ": secret key");

            // KEM Enc
            HqcKemGenerator hqcEncCipher = new HqcKemGenerator(new FixedSecureRandom(new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(seed) }));
            ISecretWithEncapsulation secWenc = hqcEncCipher.GenerateEncapsulated(pubParams);
            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");

            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc key");

            // KEM Dec
            HqcKemExtractor hqcDecCipher = new HqcKemExtractor(privParams);

            byte[] dec_key = hqcDecCipher.ExtractSecret(generated_cipher_text);

            Assert.True(Arrays.AreEqual(dec_key, ss), name + " " + count + ": kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/hqc", name)))
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
                        RunTestVector(name, buf);
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    RunTestVector(name, buf);
                    buf.Clear();
                }
            }
        }
    }
}
