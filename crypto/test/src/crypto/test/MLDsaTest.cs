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
    public class MLDsaTest
    {
        private delegate void RunTestVector(string name, Dictionary<string, string> data);

        private static readonly Dictionary<string, MLDsaParameters> Parameters =
            new Dictionary<string, MLDsaParameters>()
        {
            { "ML-DSA-44", MLDsaParameters.ML_DSA_44 },
            { "ML-DSA-65", MLDsaParameters.ML_DSA_65 },
            { "ML-DSA-87", MLDsaParameters.ML_DSA_87 },
        };

        private static readonly Dictionary<string, MLDsaParameters> FileParameters =
            new Dictionary<string, MLDsaParameters>()
        {
            { "keyGen_ML-DSA-44.txt", MLDsaParameters.ML_DSA_44 },
            { "keyGen_ML-DSA-65.txt", MLDsaParameters.ML_DSA_65 },
            { "keyGen_ML-DSA-87.txt", MLDsaParameters.ML_DSA_87 },
            { "sigGen_ML-DSA-44.txt", MLDsaParameters.ML_DSA_44 },
            { "sigGen_ML-DSA-65.txt", MLDsaParameters.ML_DSA_65 },
            { "sigGen_ML-DSA-87.txt", MLDsaParameters.ML_DSA_87 },
            { "sigVer_ML-DSA-44.txt", MLDsaParameters.ML_DSA_44 },
            { "sigVer_ML-DSA-65.txt", MLDsaParameters.ML_DSA_65 },
            { "sigVer_ML-DSA-87.txt", MLDsaParameters.ML_DSA_87 },
        };

        private static readonly string[] KeyGenFiles =
        {
            "keyGen_ML-DSA-44.txt",
            "keyGen_ML-DSA-65.txt",
            "keyGen_ML-DSA-87.txt",
        };

        private static readonly string[] SigGenFiles =
        {
            "sigGen_ML-DSA-44.txt",
            "sigGen_ML-DSA-65.txt",
            "sigGen_ML-DSA-87.txt",
        };

        private static readonly string[] SigVerFiles =
        {
            "sigVer_ML-DSA-44.txt",
            "sigVer_ML-DSA-65.txt",
            "sigVer_ML-DSA-87.txt",
        };

        [Test]
        public void Consistency()
        {
            var msg = new byte[2048];
            var random = new SecureRandom();

            var kpg = new MLDsaKeyPairGenerator();

            foreach (var parameters in
                new[]{ MLDsaParameters.ML_DSA_44, MLDsaParameters.ML_DSA_65, MLDsaParameters.ML_DSA_87 })
            {
                kpg.Init(new MLDsaKeyGenerationParameters(random, parameters));

                int msgLen = 0;
                do
                {
                    for (int i = 0; i < 3; ++i)
                    {
                        var kp = kpg.GenerateKeyPair();

                        var signer = new MLDsaSigner();

                        for (int j = 0; j < 3; ++j)
                        {
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

                    msgLen += msgLen < 128 ? 1 : 17;
                }
                while (msgLen <= 2048);
            }
        }

        [TestCaseSource(nameof(KeyGenFiles))]
        [Parallelizable(ParallelScope.All)]
        public void KeyGen(string fileName)
        {
            RunTestVectors("pqc/crypto/dilithium/acvp", fileName, (name, data) =>
            {
                byte[] seed = Hex.Decode(data["seed"]);
                byte[] pk = Hex.Decode(data["pk"]);
                byte[] sk = Hex.Decode(data["sk"]);

                var random = FixedSecureRandom.From(seed);
                var parameters = FileParameters[name];

                var kpg = new MLDsaKeyPairGenerator();
                kpg.Init(new MLDsaKeyGenerationParameters(random, parameters));

                var kp = kpg.GenerateKeyPair();

                MLDsaPublicKeyParameters pubParams = (MLDsaPublicKeyParameters)PublicKeyFactory.CreateKey(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((MLDsaPublicKeyParameters)kp.Public));
                MLDsaPrivateKeyParameters privParams = (MLDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo((MLDsaPrivateKeyParameters)kp.Private));

                Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + ": public key");
                Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + ": secret key");
            });
        }

        //[TestCaseSource(nameof(SigGenFiles))]
        //[Parallelizable(ParallelScope.All)]
        //public void SigGen(string fileName)
        //{
        //    RunTestVectors("pqc/crypto/dilithium/acvp", fileName, (name, data) =>
        //    {
        //        byte[] sk = Hex.Decode(data["sk"]);
        //        byte[] message = Hex.Decode(data["message"]);
        //        byte[] signature = Hex.Decode(data["signature"]);

        //        bool deterministic = !data.ContainsKey("rnd");

        //        byte[] rnd;
        //        if (deterministic)
        //        {
        //            rnd = new byte[32];
        //        }
        //        else
        //        {
        //            rnd = Hex.Decode(data["rnd"]);
        //        }

        //        var parameters = FileParameters[name];
        //        var privateKey = new MLDsaPrivateKeyParameters(parameters, sk);

        //        byte[] generated = privateKey.SignInternal(rnd, message, 0, message.Length);

        //        Assert.True(Arrays.AreEqual(generated, signature));
        //    });
        //}

        //[Test]
        //[Parallelizable]
        //public void SigGenCombined()
        //{
        //    RunTestVectors("pqc/crypto/mldsa", "ML-DSA-sigGen.txt", (name, data) =>
        //    {
        //        byte[] sk = Hex.Decode(data["sk"]);
        //        byte[] message = Hex.Decode(data["message"]);
        //        byte[] signature = Hex.Decode(data["signature"]);

        //        bool deterministic = bool.Parse(data["deterministic"]);

        //        byte[] rnd;
        //        if (deterministic)
        //        {
        //            rnd = new byte[32];
        //        }
        //        else
        //        {
        //            rnd = Hex.Decode(data["rnd"]);
        //        }

        //        var parameters = Parameters[data["parameterSet"]];
        //        var privateKey = new MLDsaPrivateKeyParameters(parameters, sk);

        //        byte[] generated = privateKey.SignInternal(rnd, message, 0, message.Length);

        //        Assert.True(Arrays.AreEqual(generated, signature));
        //    });
        //}

        //[TestCaseSource(nameof(SigVerFiles))]
        //[Parallelizable(ParallelScope.All)]
        //public void SigVer(string fileName)
        //{
        //    RunTestVectors("pqc/crypto/dilithium/acvp", fileName, (name, data) =>
        //    {
        //        bool testPassed = bool.Parse(data["testPassed"]);
        //        string reason = data["reason"];
        //        byte[] pk = Hex.Decode(data["pk"]);
        //        byte[] sk = Hex.Decode(data["sk"]);
        //        byte[] message = Hex.Decode(data["message"]);
        //        byte[] signature = Hex.Decode(data["signature"]);

        //        var parameters = FileParameters[name];
        //        var privateKey = new MLDsaPrivateKeyParameters(parameters, sk);
        //        var publicKey = new MLDsaPublicKeyParameters(parameters, pk);

        //        bool verified = publicKey.VerifyInternal(message, 0, message.Length, signature);

        //        Assert.True(verified == testPassed, "expected " + testPassed + " " + reason);
        //    });
        //}

        //[Test]
        //[Parallelizable]
        //public void SigVerCombined()
        //{
        //    RunTestVectors("pqc/crypto/mldsa", "ML-DSA-sigVer.txt", (name, data) =>
        //    {
        //        bool testPassed = bool.Parse(data["testPassed"]);
        //        byte[] pk = Hex.Decode(data["pk"]);
        //        byte[] message = Hex.Decode(data["message"]);
        //        byte[] signature = Hex.Decode(data["signature"]);

        //        var parameters = Parameters[data["parameterSet"]];
        //        var publicKey = new MLDsaPublicKeyParameters(parameters, pk);

        //        bool verified = publicKey.VerifyInternal(message, 0, message.Length, signature);

        //        Assert.True(verified == testPassed, "expected " + testPassed);
        //    });
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
                            data.Add(line.Substring(0, a).Trim(), line.Substring(a + 1).Trim());
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
