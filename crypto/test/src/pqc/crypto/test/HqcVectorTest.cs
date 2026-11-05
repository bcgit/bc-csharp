using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
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
        // the reference implementation's kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp for the HQC specification of
        // 2026-10-12 (32 is the size of the seed-only decapsulation key)
        private static readonly Dictionary<string, HqcParameters> Parameters = new Dictionary<string, HqcParameters>()
        {
            { "hqc-1/PQCkemKAT_32.rsp", HqcParameters.hqc128 },
            { "hqc-3/PQCkemKAT_32.rsp", HqcParameters.hqc192 },
            { "hqc-5/PQCkemKAT_32.rsp", HqcParameters.hqc256 },
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
                    Assert.AreEqual(parameters.SessionKeySize, encapSecret.Length * 8);
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

        [TestCaseSource(nameof(ParametersValues))]
        [Parallelizable(ParallelScope.All)]
        public void ImplicitRejectionCoverage(HqcParameters parameters)
        {
            // Regression test for the FO implicit-rejection / IND-CCA property: on re-encryption
            // failure the returned secret must be derived solely from (sigma, ciphertext) and must
            // NOT leak the decrypted message m'. Previously the conditional-move was bounded by the
            // message length k (16 for HQC-128, 24 for HQC-192) rather than the 32-byte secret, so
            // the trailing bytes kept K' = G(H(pk) || m' || salt) and gave a plaintext-checking oracle.
            var kpg = new HqcKeyPairGenerator();
            kpg.Init(new HqcKeyGenerationParameters(Random, parameters));
            var kp = kpg.GenerateKeyPair();

            var generator = new HqcKemGenerator(Random);
            var encapsulated = generator.GenerateEncapsulated(kp.Public);
            byte[] validSecret = encapsulated.GetSecret();
            byte[] ct = encapsulated.GetEncapsulation();

            var extractor = new HqcKemExtractor((HqcPrivateKeyParameters)kp.Private);

            // Sanity: an untampered ciphertext decapsulates to the encapsulated secret.
            Assert.True(Arrays.AreEqual(validSecret, extractor.ExtractSecret(ct)), parameters + ": valid decaps");

            // The 'v' part of the ciphertext follows 'u', which is N_BYTE = PublicKeyBytes - 32 bytes
            // long (the public key is a 32-byte seed plus the N_BYTE syndrome). A single-bit flip in v
            // stays within the Reed-Muller/Reed-Solomon correction capacity, so the decoded m' (and
            // hence the salt) is unchanged while the re-encryption check fails. Two such ciphertexts
            // therefore share the same (m', salt) but differ as byte strings.
            int vOffset = parameters.PublicKeyBytes - 32;

            byte[] ct1 = Arrays.Clone(ct);
            byte[] ct2 = Arrays.Clone(ct);
            ct1[vOffset] ^= 0x01;
            ct2[vOffset] ^= 0x02;

            byte[] rej1 = extractor.ExtractSecret(ct1);
            byte[] rej2 = extractor.ExtractSecret(ct2);

            // Both must be genuine rejections, not the valid secret.
            Assert.False(Arrays.AreEqual(validSecret, rej1), parameters + ": ct1 not rejected");
            Assert.False(Arrays.AreEqual(validSecret, rej2), parameters + ": ct2 not rejected");

            // Rejection must be deterministic in (sk, ct).
            Assert.True(Arrays.AreEqual(rej1, extractor.ExtractSecret(ct1)), parameters + ": rejection not deterministic");

            // The trailing 8 bytes lie in the vulnerable region for every parameter set (k <= 32),
            // and must depend on the differing ciphertext. With the bug they were a copy of K',
            // identical for ct1 and ct2.
            byte[] tail1 = Arrays.CopySegment(rej1, 24, 8);
            byte[] tail2 = Arrays.CopySegment(rej2, 24, 8);
            Assert.False(Arrays.AreEqual(tail1, tail2),
                parameters + ": rejection secret tail must depend on the ciphertext (FO implicit rejection)");
        }

        [TestCaseSource(nameof(ParametersValues))]
        [Parallelizable(ParallelScope.All)]
        public void WrongLengthEncapsulation(HqcParameters parameters)
        {
            // Regression test: Decaps reads u, v and the salt at fixed offsets and only compares u and v, so a
            // ciphertext with trailing bytes appended used to decapsulate to the honest shared secret (and a short
            // one failed inside the engine). The extractor must reject both up front.
            var kpg = new HqcKeyPairGenerator();
            kpg.Init(new HqcKeyGenerationParameters(Random, parameters));
            var kp = kpg.GenerateKeyPair();

            var encapsulated = new HqcKemGenerator(Random).GenerateEncapsulated(kp.Public);
            byte[] ct = encapsulated.GetEncapsulation();

            var extractor = new HqcKemExtractor((HqcPrivateKeyParameters)kp.Private);
            Assert.AreEqual(parameters.EncapsulationLength, extractor.EncapsulationLength);
            Assert.True(Arrays.AreEqual(encapsulated.GetSecret(), extractor.ExtractSecret(ct)),
                parameters + ": valid decaps");

            byte[] extended = Arrays.Append(ct, 0x00);
            Assert.Throws<ArgumentException>(() => extractor.ExtractSecret(extended),
                parameters + ": accepted an extended encapsulation");

            byte[] truncated = Arrays.CopySegment(ct, 0, ct.Length - 1);
            Assert.Throws<ArgumentException>(() => extractor.ExtractSecret(truncated),
                parameters + ": accepted a truncated encapsulation");

            Assert.Throws<ArgumentException>(() => extractor.ExtractSecret(new byte[0]),
                parameters + ": accepted an empty encapsulation");
            Assert.Throws<ArgumentNullException>(() => extractor.ExtractSecret(null),
                parameters + ": accepted a null encapsulation");
        }

        [TestCaseSource(nameof(ParametersValues))]
        [Parallelizable(ParallelScope.All)]
        public void SeedOnlyPrivateKey(HqcParameters parameters)
        {
            // The decapsulation key encoding is the 32-byte seedKEM (HQC specification 2026-10-12, Table 9): a key
            // rebuilt from nothing but that encoding must derive the same public key and decapsulate, and the
            // superseded expanded encoding must be refused.
            var kpg = new HqcKeyPairGenerator();
            kpg.Init(new HqcKeyGenerationParameters(Random, parameters));
            var kp = kpg.GenerateKeyPair();
            var pub = (HqcPublicKeyParameters)kp.Public;
            var priv = (HqcPrivateKeyParameters)kp.Private;

            byte[] enc = priv.GetEncoded();
            Assert.AreEqual(32, parameters.SecretKeyBytes, parameters + ": secret key size");
            Assert.AreEqual(32, enc.Length, parameters + ": encoding size");
            Assert.True(Arrays.AreEqual(enc, priv.GetPrivateKey()), parameters + ": GetPrivateKey");

            // the generator's own copy and a key re-derived from the seed agree on the public key
            Assert.True(Arrays.AreEqual(pub.GetEncoded(), priv.GetPublicKeyParameters().GetEncoded()),
                parameters + ": public key from seed");

            var rebuilt = new HqcPrivateKeyParameters(parameters, enc);
            Assert.True(Arrays.AreEqual(pub.GetEncoded(), rebuilt.GetPublicKeyParameters().GetEncoded()),
                parameters + ": public key from rebuilt seed");

            var encapsulated = new HqcKemGenerator(Random).GenerateEncapsulated(pub);
            byte[] fromRebuilt = new HqcKemExtractor(rebuilt).ExtractSecret(encapsulated.GetEncapsulation());
            Assert.True(Arrays.AreEqual(encapsulated.GetSecret(), fromRebuilt),
                parameters + ": decaps with rebuilt key");

            // the expanded layout of the 2025-08-22 specification is no longer an encoding
            foreach (int oldSize in new int[]{ 2321, 4602, 7333 })
            {
                Assert.Throws<ArgumentException>(() => new HqcPrivateKeyParameters(parameters, new byte[oldSize]),
                    parameters + ": accepted a " + oldSize + " byte private key");
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

            // the 2026-10-12 reference KAT harness went back to the NIST AES-256 CTR-DRBG (lib/nist-rng/rng.c,
            // randombytes_init(seed, NULL, 256)); the 2025-08-22 one drew from SHAKE256(seed || 0x00)
            var random = new NistSecureRandom(seed, null);
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
    }
}
