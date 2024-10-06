using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
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
            { "keyGen_SLH-DSA-SHA2-128s.txt", SlhDsaParameters.SLH_DSA_SHA2_128s },
            { "keyGen_SLH-DSA-SHA2-192f.txt", SlhDsaParameters.SLH_DSA_SHA2_192f },
            { "keyGen_SLH-DSA-SHAKE-192s.txt", SlhDsaParameters.SLH_DSA_SHAKE_192s },
            { "keyGen_SLH-DSA-SHAKE-256f.txt", SlhDsaParameters.SLH_DSA_SHAKE_256f },
            { "sigGen_SLH-DSA-SHA2-192s.txt", SlhDsaParameters.SLH_DSA_SHA2_192s },
            { "sigGen_SLH-DSA-SHA2-256f.txt", SlhDsaParameters.SLH_DSA_SHA2_256f },
            { "sigGen_SLH-DSA-SHAKE-128f.txt", SlhDsaParameters.SLH_DSA_SHAKE_128f },
            { "sigGen_SLH-DSA-SHAKE-192s.txt", SlhDsaParameters.SLH_DSA_SHAKE_192s },
            { "sigGen_SLH-DSA-SHAKE-256f.txt", SlhDsaParameters.SLH_DSA_SHAKE_256f },
            { "sigVer_SLH-DSA-SHA2-192s.txt", SlhDsaParameters.SLH_DSA_SHA2_192s },
            { "sigVer_SLH-DSA-SHA2-256f.txt", SlhDsaParameters.SLH_DSA_SHA2_256f },
            { "sigVer_SLH-DSA-SHAKE-128f.txt", SlhDsaParameters.SLH_DSA_SHAKE_128f },
            { "sigVer_SLH-DSA-SHAKE-192s.txt", SlhDsaParameters.SLH_DSA_SHAKE_192s },
            { "sigVer_SLH-DSA-SHAKE-256f.txt", SlhDsaParameters.SLH_DSA_SHAKE_256f },
        };

        private static readonly Dictionary<string, SlhDsaParameters> Parameters =
            new Dictionary<string, SlhDsaParameters>()
        {
            { "SLH-DSA-SHA2-128f", SlhDsaParameters.SLH_DSA_SHA2_128f },
            { "SLH-DSA-SHA2-128s", SlhDsaParameters.SLH_DSA_SHA2_128s },
            { "SLH-DSA-SHA2-192f", SlhDsaParameters.SLH_DSA_SHA2_192f },
            { "SLH-DSA-SHA2-192s", SlhDsaParameters.SLH_DSA_SHA2_192s },
            { "SLH-DSA-SHA2-256f", SlhDsaParameters.SLH_DSA_SHA2_256f },
            { "SLH-DSA-SHA2-256s", SlhDsaParameters.SLH_DSA_SHA2_256s },
            { "SLH-DSA-SHAKE-128f", SlhDsaParameters.SLH_DSA_SHAKE_128f },
            { "SLH-DSA-SHAKE-128s", SlhDsaParameters.SLH_DSA_SHAKE_128s },
            { "SLH-DSA-SHAKE-192f", SlhDsaParameters.SLH_DSA_SHAKE_192f },
            { "SLH-DSA-SHAKE-192s", SlhDsaParameters.SLH_DSA_SHAKE_192s },
            { "SLH-DSA-SHAKE-256s", SlhDsaParameters.SLH_DSA_SHAKE_256s },
            { "SLH-DSA-SHAKE-256f", SlhDsaParameters.SLH_DSA_SHAKE_256f },
        };

        private static readonly IEnumerable<SlhDsaParameters> ParameterSets = Parameters.Values;

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

        [TestCaseSource(nameof(ParameterSets))]
        [Parallelizable(ParallelScope.All)]
        public void Consistency(SlhDsaParameters parameters)
        {
            var msg = new byte[256];
            var random = new SecureRandom();

            var kpg = new SlhDsaKeyPairGenerator();
            kpg.Init(new SlhDsaKeyGenerationParameters(random, parameters));

            for (int i = 0; i < 4; ++i)
            {
                var kp = kpg.GenerateKeyPair();

                var signer = new SlhDsaSigner();

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

        private static void ImplKeyGen(string name, Dictionary<string, string> data,
            SlhDsaParameters parameters)
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

        //private static void ImplSigGen(string name, Dictionary<string, string> data,
        //    SlhDsaParameters parameters)
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

        //    var privateKey = new SlhDsaPrivateKeyParameters(parameters, sk);

        //    byte[] generated = privateKey.SignInternal(optRand: additionalRandomness, message, 0, message.Length);

        //    Assert.True(Arrays.AreEqual(generated, signature));
        //}

        //private static void ImplSigVer(string name, Dictionary<string, string> data,
        //    SlhDsaParameters parameters)
        //{
        //    bool testPassed = bool.Parse(data["testPassed"]);
        //    byte[] pk = Hex.Decode(data["pk"]);
        //    byte[] message = Hex.Decode(data["message"]);
        //    byte[] signature = Hex.Decode(data["signature"]);

        //    var publicKey = new SlhDsaPublicKeyParameters(parameters, pk);

        //    bool verified = publicKey.VerifyInternal(message, 0, message.Length, signature);

        //    Assert.True(verified == testPassed, "expected " + testPassed);
        //}

        private static void RunTestVectors(string homeDir, string fileName, RunTestVector runTestVector)
        {
            var data = new Dictionary<string, string>();
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
                        runTestVector(fileName, data);
                        data.Clear();
                    }
                }

                if (data.Count > 0)
                {
                    runTestVector(fileName, data);
                    data.Clear();
                }
            }
        }
    }
}
