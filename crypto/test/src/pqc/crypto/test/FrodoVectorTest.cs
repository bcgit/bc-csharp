using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class FrodoVectorTest
    {
        private static readonly Dictionary<string, FrodoParameters> Parameters = new Dictionary<string, FrodoParameters>()
        {
            { "PQCkemKAT_19888.rsp", FrodoParameters.frodokem640aes },
            { "PQCkemKAT_31296.rsp", FrodoParameters.frodokem976aes },
            { "PQCkemKAT_43088.rsp", FrodoParameters.frodokem1344aes },
            { "PQCkemKAT_19888_shake.rsp", FrodoParameters.frodokem640shake },
            { "PQCkemKAT_31296_shake.rsp", FrodoParameters.frodokem976shake },
            { "PQCkemKAT_43088_shake.rsp", FrodoParameters.frodokem1344shake },
        };

        private static readonly string[] TestVectorFilesAes =
        {
            "PQCkemKAT_19888.rsp",
            "PQCkemKAT_31296.rsp",
            "PQCkemKAT_43088.rsp",
        };

        private static readonly string[] TestVectorFilesShake =
        {
            "PQCkemKAT_19888_shake.rsp",
            "PQCkemKAT_31296_shake.rsp",
            "PQCkemKAT_43088_shake.rsp",
        };

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, FrodoParameters.frodokem640aes.DefaultKeySize);
            Assert.AreEqual(128, FrodoParameters.frodokem640shake.DefaultKeySize);
            Assert.AreEqual(192, FrodoParameters.frodokem976aes.DefaultKeySize);
            Assert.AreEqual(192, FrodoParameters.frodokem976shake.DefaultKeySize);
            Assert.AreEqual(256, FrodoParameters.frodokem1344aes.DefaultKeySize);
            Assert.AreEqual(256, FrodoParameters.frodokem1344shake.DefaultKeySize);
        }

        [TestCaseSource(nameof(TestVectorFilesAes))]
        [Parallelizable(ParallelScope.All)]
        public void TVAes(string testVectorFile) =>
            PqcTestUtilities.RunTestVectors("pqc/crypto/frodo", testVectorFile, sampleOnly: true, RunTestVector);

        [TestCaseSource(nameof(TestVectorFilesShake))]
        [Parallelizable(ParallelScope.All)]
        public void TVShake(string testVectorFile) =>
            PqcTestUtilities.RunTestVectors("pqc/crypto/frodo", testVectorFile, sampleOnly: true, RunTestVector);

        private static void RunTestVector(string path, Dictionary<string, string> data)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
            byte[] pk = Hex.Decode(data["pk"]);     // public key
            byte[] sk = Hex.Decode(data["sk"]);     // private key
            byte[] ct = Hex.Decode(data["ct"]);     // ciphertext
            byte[] ss = Hex.Decode(data["ss"]);     // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FrodoParameters frodoParameters = Parameters[path];

            FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
            FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, frodoParameters);
            //
            // Generate keys and test.
            //
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
                PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((FrodoPublicKeyParameters)kp.Public));
            FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
                PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((FrodoPrivateKeyParameters)kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetPublicKey()), $"{path} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), $"{path} {count} : secret key");

            // kem_enc
            FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(random);
            ISecretWithEncapsulation secWenc = frodoEncCipher.GenerateEncapsulated(pubParams);
            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), path + " " + count + ": kem_enc cipher text");
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, secret), path + " " + count + ": kem_enc key");

            // kem_dec
            FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParams);

            byte[] dec_key = frodoDecCipher.ExtractSecret(generated_cipher_text);

            Assert.True(frodoParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, ss), $"{path} {count}: kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), $"{path} {count}: kem_dec key");
        }
    }
}
