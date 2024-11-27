using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Crypto.Tests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class SlhDsaTest
    {
        private delegate void RunTestVector(string name, Dictionary<string, string> data);

        private static readonly Dictionary<string, SlhDsaParameters> AcvpFileParameters =
            new Dictionary<string, SlhDsaParameters>()
        {
            { "keyGen_SLH-DSA-SHA2-128s.txt", SlhDsaParameters.slh_dsa_sha2_128s },
            { "keyGen_SLH-DSA-SHA2-192f.txt", SlhDsaParameters.slh_dsa_sha2_192f },
            { "keyGen_SLH-DSA-SHAKE-192s.txt", SlhDsaParameters.slh_dsa_shake_192s },
            { "keyGen_SLH-DSA-SHAKE-256f.txt", SlhDsaParameters.slh_dsa_shake_256f },
            { "sigGen_SLH-DSA-SHA2-192s.txt", SlhDsaParameters.slh_dsa_sha2_192s },
            { "sigGen_SLH-DSA-SHA2-256f.txt", SlhDsaParameters.slh_dsa_sha2_256f },
            { "sigGen_SLH-DSA-SHAKE-128f.txt", SlhDsaParameters.slh_dsa_shake_128f },
            { "sigGen_SLH-DSA-SHAKE-192s.txt", SlhDsaParameters.slh_dsa_shake_192s },
            { "sigGen_SLH-DSA-SHAKE-256f.txt", SlhDsaParameters.slh_dsa_shake_256f },
            { "sigVer_SLH-DSA-SHA2-192s.txt", SlhDsaParameters.slh_dsa_sha2_192s },
            { "sigVer_SLH-DSA-SHA2-256f.txt", SlhDsaParameters.slh_dsa_sha2_256f },
            { "sigVer_SLH-DSA-SHAKE-128f.txt", SlhDsaParameters.slh_dsa_shake_128f },
            { "sigVer_SLH-DSA-SHAKE-192s.txt", SlhDsaParameters.slh_dsa_shake_192s },
            { "sigVer_SLH-DSA-SHAKE-256f.txt", SlhDsaParameters.slh_dsa_shake_256f },
        };

        private static readonly Dictionary<string, SlhDsaParameters> ContextFastFileParameters =
            new Dictionary<string, SlhDsaParameters>()
        {
            { "sha2-128f.rsp", SlhDsaParameters.slh_dsa_sha2_128f },
            { "sha2-128f-sha256.rsp", SlhDsaParameters.slh_dsa_sha2_128f_with_sha256 },
            { "sha2-192f.rsp", SlhDsaParameters.slh_dsa_sha2_192f },
            { "sha2-192f-sha512.rsp", SlhDsaParameters.slh_dsa_sha2_192f_with_sha512 },
            { "sha2-256f.rsp", SlhDsaParameters.slh_dsa_sha2_256f },
            { "sha2-256f-sha512.rsp", SlhDsaParameters.slh_dsa_sha2_256f_with_sha512 },
            { "shake-128f.rsp", SlhDsaParameters.slh_dsa_shake_128f },
            { "shake-128f-shake128.rsp", SlhDsaParameters.slh_dsa_shake_128f_with_shake128 },
            { "shake-192f.rsp", SlhDsaParameters.slh_dsa_shake_192f },
            { "shake-192f-shake256.rsp", SlhDsaParameters.slh_dsa_shake_192f_with_shake256 },
            { "shake-256f.rsp", SlhDsaParameters.slh_dsa_shake_256f },
            { "shake-256f-shake256.rsp", SlhDsaParameters.slh_dsa_shake_256f_with_shake256 },
        };

        private static readonly IEnumerable<string> ContextFastFiles = ContextFastFileParameters.Keys;

        private static readonly Dictionary<string, SlhDsaParameters> ContextSlowFileParameters =
            new Dictionary<string, SlhDsaParameters>()
        {
            { "sha2-128s.rsp", SlhDsaParameters.slh_dsa_sha2_128s },
            { "sha2-128s-sha256.rsp", SlhDsaParameters.slh_dsa_sha2_128s_with_sha256 },
            { "sha2-192s.rsp", SlhDsaParameters.slh_dsa_sha2_192s },
            { "sha2-192s-sha512.rsp", SlhDsaParameters.slh_dsa_sha2_192s_with_sha512 },
            { "sha2-256s.rsp", SlhDsaParameters.slh_dsa_sha2_256s },
            { "sha2-256s-sha512.rsp", SlhDsaParameters.slh_dsa_sha2_256s_with_sha512 },
            { "shake-128s.rsp", SlhDsaParameters.slh_dsa_shake_128s },
            { "shake-128s-shake128.rsp", SlhDsaParameters.slh_dsa_shake_128s_with_shake128 },
            { "shake-192s.rsp", SlhDsaParameters.slh_dsa_shake_192s },
            { "shake-192s-shake256.rsp", SlhDsaParameters.slh_dsa_shake_192s_with_shake256 },
            { "shake-256s.rsp", SlhDsaParameters.slh_dsa_shake_256s },
            { "shake-256s-shake256.rsp", SlhDsaParameters.slh_dsa_shake_256s_with_shake256 },
        };

        private static readonly IEnumerable<string> ContextSlowFiles = ContextSlowFileParameters.Keys;

        private static readonly Dictionary<string, SlhDsaParameters> Parameters =
            new Dictionary<string, SlhDsaParameters>()
        {
            { "SLH-DSA-SHA2-128f", SlhDsaParameters.slh_dsa_sha2_128f },
            { "SLH-DSA-SHA2-128s", SlhDsaParameters.slh_dsa_sha2_128s },
            { "SLH-DSA-SHA2-192f", SlhDsaParameters.slh_dsa_sha2_192f },
            { "SLH-DSA-SHA2-192s", SlhDsaParameters.slh_dsa_sha2_192s },
            { "SLH-DSA-SHA2-256f", SlhDsaParameters.slh_dsa_sha2_256f },
            { "SLH-DSA-SHA2-256s", SlhDsaParameters.slh_dsa_sha2_256s },
            { "SLH-DSA-SHAKE-128f", SlhDsaParameters.slh_dsa_shake_128f },
            { "SLH-DSA-SHAKE-128s", SlhDsaParameters.slh_dsa_shake_128s },
            { "SLH-DSA-SHAKE-192f", SlhDsaParameters.slh_dsa_shake_192f },
            { "SLH-DSA-SHAKE-192s", SlhDsaParameters.slh_dsa_shake_192s },
            { "SLH-DSA-SHAKE-256s", SlhDsaParameters.slh_dsa_shake_256s },
            { "SLH-DSA-SHAKE-256f", SlhDsaParameters.slh_dsa_shake_256f },
        };

        private static readonly IEnumerable<SlhDsaParameters> ParametersValues = Parameters.Values;

        private static readonly string[] KeyGenAcvpFiles =
        {
            "keyGen_SLH-DSA-SHA2-128s.txt",
            "keyGen_SLH-DSA-SHA2-192f.txt",
            "keyGen_SLH-DSA-SHAKE-192s.txt",
            "keyGen_SLH-DSA-SHAKE-256f.txt",
        };

        private static readonly string[] SigGenAcvpFiles =
        {
            "sigGen_SLH-DSA-SHA2-192s.txt",
            "sigGen_SLH-DSA-SHA2-256f.txt",
            "sigGen_SLH-DSA-SHAKE-128f.txt",
            "sigGen_SLH-DSA-SHAKE-192s.txt",
            "sigGen_SLH-DSA-SHAKE-256f.txt",
        };

        private static readonly string[] SigVerAcvpFiles =
        {
            "sigVer_SLH-DSA-SHA2-192s.txt",
            "sigVer_SLH-DSA-SHA2-256f.txt",
            "sigVer_SLH-DSA-SHAKE-128f.txt",
            "sigVer_SLH-DSA-SHAKE-192s.txt",
            "sigVer_SLH-DSA-SHAKE-256f.txt",
        };

        [TestCaseSource(nameof(ParametersValues))]
        [Parallelizable(ParallelScope.All)]
        public void Consistency(SlhDsaParameters parameters)
        {
            var msg = new byte[256];
            var random = new SecureRandom();

            var kpg = new SlhDsaKeyPairGenerator();
            kpg.Init(new SlhDsaKeyGenerationParameters(random, parameters));

            {
                var kp = kpg.GenerateKeyPair();

                var signer = new SlhDsaSigner(parameters, deterministic: false);

                {
                    int msgLen = random.Next(msg.Length + 1);
                    random.NextBytes(msg, 0, msgLen);

                    // sign
                    signer.Init(true, new ParametersWithRandom(kp.Private, random));
                    signer.BlockUpdate(msg, 0, msgLen);
                    var signature = signer.GenerateSignature();

                    // verify
                    signer.Init(false, kp.Public);
                    signer.BlockUpdate(msg, 0, msgLen);
                    bool shouldVerify = signer.VerifySignature(signature);

                    Assert.True(shouldVerify);
                }
            }
        }

        [TestCaseSource(nameof(ContextFastFiles))]
        [Parallelizable]
        public void ContextFast(string fileName)
        {
            RunTestVectors("pqc/crypto/slhdsa", fileName, sampleOnly: true,
                (name, data) => ImplContext(name, data, ContextFastFileParameters[name]));
        }

        [TestCaseSource(nameof(ContextSlowFiles)), Explicit]
        [Parallelizable]
        public void ContextSlow(string fileName)
        {
            RunTestVectors("pqc/crypto/slhdsa", fileName, sampleOnly: true,
                (name, data) => ImplContext(name, data, ContextSlowFileParameters[name]));
        }

        [Test]
        [Parallelizable]
        public void KeyGen()
        {
            RunTestVectors("pqc/crypto/slhdsa", "SLH-DSA-keyGen.txt",
                (name, data) => ImplKeyGen(name, data, Parameters[data["parameterSet"]]));
        }

        [TestCaseSource(nameof(KeyGenAcvpFiles))]
        [Parallelizable(ParallelScope.All)]
        public void KeyGenAcvp(string fileName)
        {
            RunTestVectors("pqc/crypto/slhdsa/acvp", fileName,
                (name, data) => ImplKeyGen(name, data, AcvpFileParameters[name]));
        }

        //[Test]
        //[Parallelizable]
        //public void SigGen()
        //{
        //    RunTestVectors("pqc/crypto/slhdsa", "SLH-DSA-sigGen.txt",
        //        (name, data) => ImplSigGen(name, data, Parameters[data["parameterSet"]]));
        //}

        //[TestCaseSource(nameof(SigGenAcvpFiles))]
        //[Parallelizable(ParallelScope.All)]
        //public void SigGenAcvp(string fileName)
        //{
        //    RunTestVectors("pqc/crypto/slhdsa/acvp", fileName,
        //        (name, data) => ImplSigGen(name, data, AcvpFileParameters[name]));
        //}

        //[Test]
        //[Parallelizable]
        //public void SigVer()
        //{
        //    RunTestVectors("pqc/crypto/slhdsa", "SLH-DSA-sigVer.txt",
        //        (name, data) => ImplSigVer(name, data, Parameters[data["parameterSet"]]));
        //}

        //[TestCaseSource(nameof(SigVerAcvpFiles))]
        //[Parallelizable(ParallelScope.All)]
        //public void SigVerAcvp(string fileName)
        //{
        //    RunTestVectors("pqc/crypto/slhdsa/acvp", fileName,
        //        (name, data) => ImplSigVer(name, data, AcvpFileParameters[name]));
        //}

        private static void ImplContext(string name, Dictionary<string, string> data, SlhDsaParameters parameters)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]);
            byte[] msg = Hex.Decode(data["msg"]);
            byte[] pk = Hex.Decode(data["pk"]);
            byte[] sk = Hex.Decode(data["sk"]);
            byte[] sm = Hex.Decode(data["sm"]);
            byte[] optrand = Hex.Decode(data["optrand"]);

            byte[] context = null;
            if (data.TryGetValue("context", out var contextValue))
            {
                context = Hex.Decode(contextValue);
            }

            var random = FixedSecureRandom.From(seed);

            var kpg = new SlhDsaKeyPairGenerator();
            kpg.Init(new SlhDsaKeyGenerationParameters(random, parameters));

            var kp = kpg.GenerateKeyPair();

            var publicKey = (SlhDsaPublicKeyParameters)kp.Public;
            var privateKey = (SlhDsaPrivateKeyParameters)kp.Private;

            Assert.True(Arrays.AreEqual(pk, publicKey.GetEncoded()), $"{name} {count}: public key");
            Assert.True(Arrays.AreEqual(sk, privateKey.GetEncoded()), $"{name} {count}: secret key");

            var publicKeyRT = (SlhDsaPublicKeyParameters)PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));
            var privateKeyRT = (SlhDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey));

            Assert.True(Arrays.AreEqual(pk, publicKeyRT.GetEncoded()), $"{name} {count}: public key (round-trip)");
            Assert.True(Arrays.AreEqual(sk, privateKeyRT.GetEncoded()), $"{name} {count}: secret key (round-trip)");

            // Note that this is not a deterministic signature test, since we are given "optrand"
            ISigner sig;
            if (parameters.IsPreHash)
            {
                sig = new HashSlhDsaSigner(parameters, deterministic: false);
            }
            else
            {
                sig = new SlhDsaSigner(parameters, deterministic: false);
            }

            // The current test data is a bit weird and uses internal signing when no explicit context provided.
            if (context == null)
            {
                //byte[] generated = privateKey.SignInternal(optrand, msg, 0, msg.Length);
                //Assert.True(Arrays.AreEqual(sm, generated), $"{name} {count}: SignInternal");

                //bool shouldVerify = publicKey.VerifyInternal(msg, 0, msg.Length, sm);
                //Assert.True(shouldVerify, $"{name} {count}: VerifyInternal");
            }
            else
            {
                sig.Init(forSigning: true,
                    ParameterUtilities.WithContext(
                        ParameterUtilities.WithRandom(privateKey, FixedSecureRandom.From(optrand)),
                        context));
                sig.BlockUpdate(msg, 0, msg.Length);
                byte[] generated = sig.GenerateSignature();
                Assert.True(Arrays.AreEqual(sm, generated), $"{name} {count}: GenerateSignature");

                sig.Init(forSigning: false, ParameterUtilities.WithContext(publicKey, context));
                sig.BlockUpdate(msg, 0, msg.Length);
                bool shouldVerify = sig.VerifySignature(sm);
                Assert.True(shouldVerify, $"{name} {count}: VerifySignature");
            }
        }

        private static void ImplKeyGen(string name, Dictionary<string, string> data, SlhDsaParameters parameters)
        {
            byte[] skSeed = Hex.Decode(data["skSeed"]);
            byte[] skPrf = Hex.Decode(data["skPrf"]);
            byte[] pkSeed = Hex.Decode(data["pkSeed"]);
            byte[] pk = Hex.Decode(data["pk"]);
            byte[] sk = Hex.Decode(data["sk"]);

            var random = FixedSecureRandom.From(Arrays.ConcatenateAll(skSeed, skPrf, pkSeed));

            var kpg = new SlhDsaKeyPairGenerator();
            kpg.Init(new SlhDsaKeyGenerationParameters(random, parameters));

            var kp = kpg.GenerateKeyPair();

            SlhDsaPublicKeyParameters pubParams = (SlhDsaPublicKeyParameters)PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((SlhDsaPublicKeyParameters)kp.Public));
            SlhDsaPrivateKeyParameters privParams = (SlhDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo((SlhDsaPrivateKeyParameters)kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + ": secret key");
        }

        //private static void ImplSigGen(string name, Dictionary<string, string> data, SlhDsaParameters parameters)
        //{
        //    byte[] sk = Hex.Decode(data["sk"]);
        //    byte[] message = Hex.Decode(data["message"]);
        //    byte[] signature = Hex.Decode(data["signature"]);

        //    bool deterministic = !data.ContainsKey("additionalRandomness");

        //    byte[] additionalRandomness = null;
        //    if (!deterministic)
        //    {
        //        additionalRandomness = Hex.Decode(data["additionalRandomness"]);
        //    }

        //    var privateKey = SlhDsaPrivateKeyParameters.FromEncoding(parameters, sk);

        //    byte[] generated = privateKey.SignInternal(optRand: additionalRandomness, message, 0, message.Length);

        //    Assert.True(Arrays.AreEqual(generated, signature));
        //}

        //private static void ImplSigVer(string name, Dictionary<string, string> data, SlhDsaParameters parameters)
        //{
        //    bool testPassed = bool.Parse(data["testPassed"]);
        //    byte[] pk = Hex.Decode(data["pk"]);
        //    byte[] message = Hex.Decode(data["message"]);
        //    byte[] signature = Hex.Decode(data["signature"]);

        //    var publicKey = SlhDsaPublicKeyParameters.FromEncoding(parameters, pk);

        //    bool verified = publicKey.VerifyInternal(message, 0, message.Length, signature);

        //    Assert.True(verified == testPassed, "expected " + testPassed);
        //}

        private static void RunTestVectors(string homeDir, string fileName, RunTestVector runTestVector) =>
            RunTestVectors(homeDir, fileName, sampleOnly: false, runTestVector);

        private static void RunTestVectors(string homeDir, string fileName, bool sampleOnly,
            RunTestVector runTestVector)
        {
            var data = new Dictionary<string, string>();
            var sampler = sampleOnly ? new TestSampler() : null;
            using (var src = new StreamReader(SimpleTest.FindTestResource(homeDir, fileName)))
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
                        if (a >= 0)
                        {
                            data[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (data.Count > 0)
                    {
                        if (sampler == null || !sampler.SkipTest(data["count"]))
                        {
                            runTestVector(fileName, data);
                        }
                        data.Clear();
                    }
                }

                if (data.Count > 0)
                {
                    if (sampler == null || !sampler.SkipTest(data["count"]))
                    {
                        runTestVector(fileName, data);
                    }
                    data.Clear();
                }
            }
        }
    }
}
