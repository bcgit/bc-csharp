using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class NtruPrimeVectorTest
    {
        private static readonly Dictionary<string, NtruLPRimeParameters> ParametersNtruLP = new Dictionary<string, NtruLPRimeParameters>()
        {
            { "ntrulpr653.rsp", NtruLPRimeParameters.ntrulpr653 },
            { "ntrulpr761.rsp", NtruLPRimeParameters.ntrulpr761 },
            { "ntrulpr857.rsp", NtruLPRimeParameters.ntrulpr857 },
            { "ntrulpr953.rsp", NtruLPRimeParameters.ntrulpr953 },
            { "ntrulpr1013.rsp", NtruLPRimeParameters.ntrulpr1013 },
            { "ntrulpr1277.rsp", NtruLPRimeParameters.ntrulpr1277 },
        };

        private static readonly Dictionary<string, SNtruPrimeParameters> ParametersSNtruP = new Dictionary<string, SNtruPrimeParameters>()
        {
            { "sntrup653.rsp", SNtruPrimeParameters.sntrup653 },
            { "sntrup761.rsp", SNtruPrimeParameters.sntrup761 },
            { "sntrup857.rsp", SNtruPrimeParameters.sntrup857 },
            { "sntrup953.rsp", SNtruPrimeParameters.sntrup953 },
            { "sntrup1013.rsp", SNtruPrimeParameters.sntrup1013 },
            { "sntrup1277.rsp", SNtruPrimeParameters.sntrup1277 },
        };

        private static readonly IEnumerable<string> TestVectorFilesNtruLP = ParametersNtruLP.Keys;

        private static readonly IEnumerable<string> TestVectorFilesSNtruP = ParametersSNtruP.Keys;

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(256, SNtruPrimeParameters.sntrup653.DefaultKeySize);
            Assert.AreEqual(256, SNtruPrimeParameters.sntrup761.DefaultKeySize);
            Assert.AreEqual(256, SNtruPrimeParameters.sntrup857.DefaultKeySize);
            Assert.AreEqual(256, SNtruPrimeParameters.sntrup953.DefaultKeySize);
            Assert.AreEqual(256, SNtruPrimeParameters.sntrup1013.DefaultKeySize);
            Assert.AreEqual(256, SNtruPrimeParameters.sntrup1277.DefaultKeySize);

            Assert.AreEqual(256, NtruLPRimeParameters.ntrulpr653.DefaultKeySize);
            Assert.AreEqual(256, NtruLPRimeParameters.ntrulpr761.DefaultKeySize);
            Assert.AreEqual(256, NtruLPRimeParameters.ntrulpr857.DefaultKeySize);
            Assert.AreEqual(256, NtruLPRimeParameters.ntrulpr953.DefaultKeySize);
            Assert.AreEqual(256, NtruLPRimeParameters.ntrulpr1013.DefaultKeySize);
            Assert.AreEqual(256, NtruLPRimeParameters.ntrulpr1277.DefaultKeySize);
        }

        [TestCaseSource(nameof(TestVectorFilesNtruLP))]
        [Parallelizable(ParallelScope.All)]
        public void TVNtruLP(string testVectorFile)
        {
            RunTestVectorNtruLPFile(testVectorFile);
        }

        [TestCaseSource(nameof(TestVectorFilesSNtruP))]
        [Parallelizable(ParallelScope.All)]
        public void TVSNtruP(string testVectorFile)
        {
            RunTestVectorSNtruPFile(testVectorFile);
        }

        private static void RunTestVectorNtruLP(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] ct = Hex.Decode(buf["ct"]);
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] ss = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruLPRimeParameters ntruPParameters = ParametersNtruLP[name];

            NtruLPRimeKeyPairGenerator kpGen = new NtruLPRimeKeyPairGenerator();
            NtruLPRimeKeyGenerationParameters genParams = new NtruLPRimeKeyGenerationParameters(random, ntruPParameters);

            // Generate the key pair
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            NtruLPRimePublicKeyParameters pubParams = (NtruLPRimePublicKeyParameters)kp.Public;
            NtruLPRimePrivateKeyParameters privParams = (NtruLPRimePrivateKeyParameters)kp.Private;

            // Check public and private key
            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), $"{name} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), $"{name} {count} : private key");

            // Encapsulation
            NtruLPRimeKemGenerator ntruPEncCipher = new NtruLPRimeKemGenerator(random);
            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
            byte[] generatedCT = secWenc.GetEncapsulation();

            // Check ciphertext
            Assert.True(Arrays.AreEqual(ct, generatedCT), name + " " + count + ": kem_enc cipher text");

            // Check secret
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), name + " " + count + ": kem_enc secret");

            // Decapsulation
            NtruLPRimeKemExtractor ntruDecCipher = new NtruLPRimeKemExtractor(privParams);
            byte[] dec_key = ntruDecCipher.ExtractSecret(generatedCT);

            // Check decapsulation secret
            Assert.True(ntruPParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), $"{name} {count}: kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), $"{name} {count}: kem_dec key");
        }

        private static void RunTestVectorNtruLPFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/ntruprime/ntrulpr", name)))
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
                            RunTestVectorNtruLP(name, buf);
                        }
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    if (!sampler.SkipTest(buf["count"]))
                    {
                        RunTestVectorNtruLP(name, buf);
                    }
                    buf.Clear();
                }
            }
        }

        private static void RunTestVectorSNtruP(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] ct = Hex.Decode(buf["ct"]);
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] ss = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SNtruPrimeParameters ntruPParameters = ParametersSNtruP[name];

            SNtruPrimeKeyPairGenerator kpGen = new SNtruPrimeKeyPairGenerator();
            SNtruPrimeKeyGenerationParameters genParams = new SNtruPrimeKeyGenerationParameters(random, ntruPParameters);

            // Generate the key pair
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            SNtruPrimePublicKeyParameters pubParams = (SNtruPrimePublicKeyParameters)kp.Public;
            SNtruPrimePrivateKeyParameters privParams = (SNtruPrimePrivateKeyParameters)kp.Private;

            // Check public and private key
            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), $"{name} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), $"{name} {count} : private key");

            // Encapsulation
            SNtruPrimeKemGenerator ntruPEncCipher = new SNtruPrimeKemGenerator(random);
            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
            byte[] generatedCT = secWenc.GetEncapsulation();

            // Check ciphertext
            Assert.True(Arrays.AreEqual(ct, generatedCT), name + " " + count + ": kem_enc cipher text");

            // Check secret
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), name + " " + count + ": kem_enc secret");

            // Decapsulation
            SNtruPrimeKemExtractor ntruDecCipher = new SNtruPrimeKemExtractor(privParams);
            byte[] dec_key = ntruDecCipher.ExtractSecret(generatedCT);

            // Check decapsulation secret
            Assert.True(ntruPParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), $"{name} {count}: kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, secret, 0, secret.Length), $"{name} {count}: kem_dec key");
        }

        private static void RunTestVectorSNtruPFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/ntruprime/sntrup", name)))
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
                            RunTestVectorSNtruP(name, buf);
                        }
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    if (!sampler.SkipTest(buf["count"]))
                    {
                        RunTestVectorSNtruP(name, buf);
                    }
                    buf.Clear();
                }
            }
        }
    }
}
