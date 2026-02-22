using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class HqcVectorTest
    {
        private static readonly Dictionary<string, HqcParameters> Parameters = new Dictionary<string, HqcParameters>()
        {
            { "PQCkemKAT_2321.rsp", HqcParameters.hqc128 },
            { "PQCkemKAT_4602.rsp", HqcParameters.hqc192 },
            { "PQCkemKAT_7333.rsp", HqcParameters.hqc256 },
        };

        private static readonly IEnumerable<HqcParameters> ParametersValues = Parameters.Values;

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        private readonly SecureRandom Random = new SecureRandom();

        [TestCaseSource(nameof(ParametersValues))]
        [Parallelizable(ParallelScope.All)]
        public void Consistency(HqcParameters parameters)
        {
            var kpg = new HqcKeyPairGenerator();
            kpg.Init(new HqcKeyGenerationParameters(Random, parameters));

            for (int i = 0; i < 10; ++i)
            {
                var kp = kpg.GenerateKeyPair();

                for (int j = 0; j < 10; ++j)
                {
                    var generator = new HqcKemGenerator(Random);
                    var encapsulated = generator.GenerateEncapsulated(kp.Public);
                    var encapSecret = encapsulated.GetSecret();
                    var encapsulation = encapsulated.GetEncapsulation();
                    Assert.AreEqual(parameters.SecretLength, encapSecret.Length);
                    Assert.AreEqual(parameters.EncapsulationLength, encapsulation.Length);

                    var extractor = new HqcKemExtractor((HqcPrivateKeyParameters)kp.Private);
                    var decapSecret = extractor.ExtractSecret(encapsulation);
                    if (!Arrays.AreEqual(encapSecret, decapSecret))
                    {
                        Assert.Fail("Consistency " + parameters + " #" + i + "[" + j + "]");
                    }
                }
            }
        }

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile) =>
            PqcTestUtilities.RunTestVectors("pqc/crypto/hqc", testVectorFile, sampleOnly: false, RunTestVector);

        private static void RunTestVector(string path, Dictionary<string, string> data)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
            byte[] pk = Hex.Decode(data["pk"]);     // public key
            byte[] sk = Hex.Decode(data["sk"]);     // private key
            byte[] ct = Hex.Decode(data["ct"]);     // ciphertext
            byte[] ss = Hex.Decode(data["ss"]);     // session key

            var random = new Shake256SecureRandom(seed);
            var hqcParameters = Parameters[path];

            var kpGen = new HqcKeyPairGenerator();
            kpGen.Init(new HqcKeyGenerationParameters(random, hqcParameters));

            // KeyGen
            var kp = kpGen.GenerateKeyPair();
            var publicKey = (HqcPublicKeyParameters)kp.Public;
            var privateKey = (HqcPrivateKeyParameters)kp.Private;

            var pubParams = (HqcPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
                PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));
            var privParams = (HqcPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
                PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), path + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), path + " " + count + ": secret key");

            // Encapsulation
            var kemGenerator = new HqcKemGenerator(random);
            ISecretWithEncapsulation secretWithEnc = kemGenerator.GenerateEncapsulated(pubParams);

            byte[] cipherText = secretWithEnc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, cipherText), path + " " + count + ": ciphertext");

            byte[] encapSecret = secretWithEnc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, encapSecret), path + " " + count + ": encapSecret");

            // Decapsulation
            var kemExtractor = new HqcKemExtractor(privParams);

            byte[] decapSecret = kemExtractor.ExtractSecret(cipherText);
            Assert.True(Arrays.AreEqual(ss, decapSecret), path + " " + count + ": decapSecret");
        }

        private class Shake256SecureRandom : SecureRandom
        {
            private readonly ShakeDigest m_xof = new ShakeDigest(256);

            internal Shake256SecureRandom(byte[] seed)
            {
                m_xof.BlockUpdate(seed, 0, seed.Length);
                m_xof.Update(0x00);
            }

            public override void NextBytes(byte[] buf) => m_xof.Output(buf, 0, buf.Length);

            public override void NextBytes(byte[] buf, int off, int len) => m_xof.Output(buf, off, len);
        }
    }
}
