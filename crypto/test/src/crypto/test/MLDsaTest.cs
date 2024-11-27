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

        private static readonly Dictionary<string, MLDsaParameters> AcvpFileParameters =
            new Dictionary<string, MLDsaParameters>()
        {
            { "keyGen_ML-DSA-44.txt", MLDsaParameters.ml_dsa_44 },
            { "keyGen_ML-DSA-65.txt", MLDsaParameters.ml_dsa_65 },
            { "keyGen_ML-DSA-87.txt", MLDsaParameters.ml_dsa_87 },
            { "sigGen_ML-DSA-44.txt", MLDsaParameters.ml_dsa_44 },
            { "sigGen_ML-DSA-65.txt", MLDsaParameters.ml_dsa_65 },
            { "sigGen_ML-DSA-87.txt", MLDsaParameters.ml_dsa_87 },
            { "sigVer_ML-DSA-44.txt", MLDsaParameters.ml_dsa_44 },
            { "sigVer_ML-DSA-65.txt", MLDsaParameters.ml_dsa_65 },
            { "sigVer_ML-DSA-87.txt", MLDsaParameters.ml_dsa_87 },
        };

        private static readonly Dictionary<string, MLDsaParameters> ContextFileParameters =
            new Dictionary<string, MLDsaParameters>()
        {
            { "mldsa44.rsp", MLDsaParameters.ml_dsa_44 },
            { "mldsa65.rsp", MLDsaParameters.ml_dsa_65 },
            { "mldsa87.rsp", MLDsaParameters.ml_dsa_87 },
            { "mldsa44Sha512.rsp", MLDsaParameters.ml_dsa_44_with_sha512 },
            { "mldsa65Sha512.rsp", MLDsaParameters.ml_dsa_65_with_sha512 },
            { "mldsa87Sha512.rsp", MLDsaParameters.ml_dsa_87_with_sha512 },
        };

        private static readonly IEnumerable<string> ContextFiles = ContextFileParameters.Keys;

        private static readonly Dictionary<string, MLDsaParameters> Parameters =
            new Dictionary<string, MLDsaParameters>()
        {
            { "ML-DSA-44", MLDsaParameters.ml_dsa_44 },
            { "ML-DSA-65", MLDsaParameters.ml_dsa_65 },
            { "ML-DSA-87", MLDsaParameters.ml_dsa_87 },
        };

        private static readonly IEnumerable<MLDsaParameters> ParametersValues = Parameters.Values;

        private static readonly string[] KeyGenAcvpFiles =
        {
            "keyGen_ML-DSA-44.txt",
            "keyGen_ML-DSA-65.txt",
            "keyGen_ML-DSA-87.txt",
        };

        private static readonly string[] SigGenAcvpFiles =
        {
            "sigGen_ML-DSA-44.txt",
            "sigGen_ML-DSA-65.txt",
            "sigGen_ML-DSA-87.txt",
        };

        private static readonly string[] SigVerAcvpFiles =
        {
            "sigVer_ML-DSA-44.txt",
            "sigVer_ML-DSA-65.txt",
            "sigVer_ML-DSA-87.txt",
        };

        [TestCaseSource(nameof(ParametersValues))]
        [Parallelizable(ParallelScope.All)]
        public void Consistency(MLDsaParameters parameters)
        {
            var msg = new byte[2048];
            var random = new SecureRandom();

            var kpg = new MLDsaKeyPairGenerator();
            kpg.Init(new MLDsaKeyGenerationParameters(random, parameters));

            int msgLen = 0;
            do
            {
                for (int i = 0; i < 2; ++i)
                {
                    var kp = kpg.GenerateKeyPair();

                    var signer = new MLDsaSigner(parameters, deterministic: false);

                    for (int j = 0; j < 2; ++j)
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

        [TestCaseSource(nameof(ContextFiles))]
        [Parallelizable]
        public void Context(string fileName)
        {
            RunTestVectors("pqc/crypto/mldsa", fileName,
                (name, data) => ImplContext(name, data, ContextFileParameters[name]));
        }

        [Test]
        [Parallelizable]
        public void KeyGen()
        {
            RunTestVectors("pqc/crypto/mldsa", "ML-DSA-keyGen.txt",
                (name, data) => ImplKeyGen(name, data, Parameters[data["parameterSet"]]));
        }

        [TestCaseSource(nameof(KeyGenAcvpFiles))]
        [Parallelizable(ParallelScope.All)]
        public void KeyGenAcvp(string fileName)
        {
            RunTestVectors("pqc/crypto/dilithium/acvp", fileName,
                (name, data) => ImplKeyGen(name, data, AcvpFileParameters[name]));
        }

        //[Test]
        //[Parallelizable]
        //public void SigGen()
        //{
        //    RunTestVectors("pqc/crypto/mldsa", "ML-DSA-sigGen.txt",
        //        (name, data) => ImplSigGen(name, data, Parameters[data["parameterSet"]]));
        //}

        //[TestCaseSource(nameof(SigGenAcvpFiles))]
        //[Parallelizable(ParallelScope.All)]
        //public void SigGenAcvp(string fileName)
        //{
        //    RunTestVectors("pqc/crypto/dilithium/acvp", fileName,
        //        (name, data) => ImplSigGen(name, data, AcvpFileParameters[name]));
        //}

        //[Test]
        //[Parallelizable]
        //public void SigVer()
        //{
        //    RunTestVectors("pqc/crypto/mldsa", "ML-DSA-sigVer.txt",
        //        (name, data) => ImplSigVer(name, data, Parameters[data["parameterSet"]]));
        //}

        //[TestCaseSource(nameof(SigVerAcvpFiles))]
        //[Parallelizable(ParallelScope.All)]
        //public void SigVerAcvp(string fileName)
        //{
        //    RunTestVectors("pqc/crypto/dilithium/acvp", fileName,
        //        (name, data) => ImplSigVer(name, data, AcvpFileParameters[name]));
        //}

        private static void ImplContext(string name, Dictionary<string, string> data, MLDsaParameters parameters)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]);
            byte[] msg = Hex.Decode(data["msg"]);
            byte[] pk = Hex.Decode(data["pk"]);
            byte[] sk = Hex.Decode(data["sk"]);
            byte[] sm = Hex.Decode(data["sm"]);

            byte[] context = null;
            if (data.TryGetValue("context", out var contextValue))
            {
                context = Hex.Decode(contextValue);
            }

            var random = FixedSecureRandom.From(seed);

            var kpg = new MLDsaKeyPairGenerator();
            kpg.Init(new MLDsaKeyGenerationParameters(random, parameters));

            var kp = kpg.GenerateKeyPair();

            var publicKey = (MLDsaPublicKeyParameters)kp.Public;
            var privateKey = (MLDsaPrivateKeyParameters)kp.Private;

            Assert.True(Arrays.AreEqual(pk, publicKey.GetEncoded()), $"{name} {count}: public key");
            Assert.True(Arrays.AreEqual(sk, privateKey.GetEncoded()), $"{name} {count}: secret key");

            var publicKeyRT = (MLDsaPublicKeyParameters)PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));
            var privateKeyRT = (MLDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey));

            Assert.True(Arrays.AreEqual(pk, publicKeyRT.GetEncoded()), $"{name} {count}: public key (round-trip)");
            Assert.True(Arrays.AreEqual(sk, privateKeyRT.GetEncoded()), $"{name} {count}: secret key (round-trip)");

            // Note that this is a deterministic signature test, since we are not given "rnd"
            ISigner sig;
            if (parameters.IsPreHash)
            {
                sig = new HashMLDsaSigner(parameters, deterministic: true);
            }
            else
            {
                sig = new MLDsaSigner(parameters, deterministic: true);
            }

            // The current test data is a bit weird and uses internal signing when no explicit context provided.
            if (context == null)
            {
                //var rnd = new byte[32]; // Deterministic
                //byte[] generated = privateKey.SignInternal(rnd, msg, 0, msg.Length);
                //Assert.True(Arrays.AreEqual(sm, generated), $"{name} {count}: SignInternal");

                //bool shouldVerify = publicKey.VerifyInternal(msg, 0, msg.Length, sm);
                //Assert.True(shouldVerify, $"{name} {count}: VerifyInternal");
            }
            else
            {
                sig.Init(forSigning: true, ParameterUtilities.WithContext(privateKey, context));
                sig.BlockUpdate(msg, 0, msg.Length);
                byte[] generated = sig.GenerateSignature();
                Assert.True(Arrays.AreEqual(sm, generated), $"{name} {count}: GenerateSignature");

                sig.Init(forSigning: false, ParameterUtilities.WithContext(publicKey, context));
                sig.BlockUpdate(msg, 0, msg.Length);
                bool shouldVerify = sig.VerifySignature(sm);
                Assert.True(shouldVerify, $"{name} {count}: VerifySignature");
            }
        }

        private static void ImplKeyGen(string name, Dictionary<string, string> data, MLDsaParameters parameters)
        {
            byte[] seed = Hex.Decode(data["seed"]);
            byte[] pk = Hex.Decode(data["pk"]);
            byte[] sk = Hex.Decode(data["sk"]);

            var random = FixedSecureRandom.From(seed);

            var kpg = new MLDsaKeyPairGenerator();
            kpg.Init(new MLDsaKeyGenerationParameters(random, parameters));

            var kp = kpg.GenerateKeyPair();

            MLDsaPublicKeyParameters pubParams = (MLDsaPublicKeyParameters)PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((MLDsaPublicKeyParameters)kp.Public));
            MLDsaPrivateKeyParameters privParams = (MLDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo((MLDsaPrivateKeyParameters)kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + ": secret key");
        }

        //private static void ImplSigGen(string name, Dictionary<string, string> data, MLDsaParameters parameters)
        //{
        //    byte[] sk = Hex.Decode(data["sk"]);
        //    byte[] message = Hex.Decode(data["message"]);
        //    byte[] signature = Hex.Decode(data["signature"]);

        //    bool deterministic = !data.ContainsKey("rnd");

        //    byte[] rnd;
        //    if (deterministic)
        //    {
        //        rnd = new byte[32];
        //    }
        //    else
        //    {
        //        rnd = Hex.Decode(data["rnd"]);
        //    }

        //    var privateKey = MLDsaPrivateKeyParameters.FromEncoding(parameters, sk);

        //    byte[] generated = privateKey.SignInternal(rnd, message, 0, message.Length);

        //    Assert.True(Arrays.AreEqual(generated, signature));
        //}

        //private static void ImplSigVer(string name, Dictionary<string, string> data, MLDsaParameters parameters)
        //{
        //    bool testPassed = bool.Parse(data["testPassed"]);
        //    byte[] pk = Hex.Decode(data["pk"]);
        //    byte[] message = Hex.Decode(data["message"]);
        //    byte[] signature = Hex.Decode(data["signature"]);

        //    var publicKey = MLDsaPublicKeyParameters.FromEncoding(parameters, pk);

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
