using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

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
        public void TVNtruLP(string testVectorFile) =>
            PqcTestUtilities.RunTestVectors("pqc/crypto/ntruprime/ntrulpr", testVectorFile, sampleOnly: true, RunTestVectorNtruLP);

        [TestCaseSource(nameof(TestVectorFilesSNtruP))]
        [Parallelizable(ParallelScope.All)]
        public void TVSNtruP(string testVectorFile) =>
            PqcTestUtilities.RunTestVectors("pqc/crypto/ntruprime/sntrup", testVectorFile, sampleOnly: true, RunTestVectorSNtruP);

        private static void RunTestVectorNtruLP(string path, Dictionary<string, string> data)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]);
            byte[] pk = Hex.Decode(data["pk"]);
            byte[] ct = Hex.Decode(data["ct"]);
            byte[] sk = Hex.Decode(data["sk"]);
            byte[] ss = Hex.Decode(data["ss"]);

            NtruLPRimeParameters ntruPParameters = ParametersNtruLP[path];
            SecureRandom random = new ReferenceDrawsRandom(new NistSecureRandom(seed, null), ntruPParameters.P);

            NtruLPRimeKeyPairGenerator kpGen = new NtruLPRimeKeyPairGenerator();
            NtruLPRimeKeyGenerationParameters genParams = new NtruLPRimeKeyGenerationParameters(random, ntruPParameters);

            // Generate the key pair
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            NtruLPRimePublicKeyParameters pubParams = (NtruLPRimePublicKeyParameters)kp.Public;
            NtruLPRimePrivateKeyParameters privParams = (NtruLPRimePrivateKeyParameters)kp.Private;

            // Check public and private key
            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), $"{path} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), $"{path} {count} : private key");

            // Encapsulation
            NtruLPRimeKemGenerator ntruPEncCipher = new NtruLPRimeKemGenerator(random);
            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
            byte[] generatedCT = secWenc.GetEncapsulation();

            // Check ciphertext
            Assert.True(Arrays.AreEqual(ct, generatedCT), path + " " + count + ": kem_enc cipher text");

            // Check secret
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), path + " " + count + ": kem_enc secret");

            // Decapsulation
            NtruLPRimeKemExtractor ntruDecCipher = new NtruLPRimeKemExtractor(privParams);
            byte[] dec_key = ntruDecCipher.ExtractSecret(generatedCT);

            // Check decapsulation secret
            Assert.True(ntruPParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), $"{path} {count}: kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), $"{path} {count}: kem_dec key");
        }

        private static void RunTestVectorSNtruP(string path, Dictionary<string, string> data)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]);
            byte[] pk = Hex.Decode(data["pk"]);
            byte[] ct = Hex.Decode(data["ct"]);
            byte[] sk = Hex.Decode(data["sk"]);
            byte[] ss = Hex.Decode(data["ss"]);

            SNtruPrimeParameters ntruPParameters = ParametersSNtruP[path];
            SecureRandom random = new ReferenceDrawsRandom(new NistSecureRandom(seed, null), ntruPParameters.P);

            SNtruPrimeKeyPairGenerator kpGen = new SNtruPrimeKeyPairGenerator();
            SNtruPrimeKeyGenerationParameters genParams = new SNtruPrimeKeyGenerationParameters(random, ntruPParameters);

            // Generate the key pair
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            SNtruPrimePublicKeyParameters pubParams = (SNtruPrimePublicKeyParameters)kp.Public;
            SNtruPrimePrivateKeyParameters privParams = (SNtruPrimePrivateKeyParameters)kp.Private;

            // Check public and private key
            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), $"{path} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), $"{path} {count} : private key");

            // Encapsulation
            SNtruPrimeKemGenerator ntruPEncCipher = new SNtruPrimeKemGenerator(random);
            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
            byte[] generatedCT = secWenc.GetEncapsulation();

            // Check ciphertext
            Assert.True(Arrays.AreEqual(ct, generatedCT), path + " " + count + ": kem_enc cipher text");

            // Check secret
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), path + " " + count + ": kem_enc secret");

            // Decapsulation
            SNtruPrimeKemExtractor ntruDecCipher = new SNtruPrimeKemExtractor(privParams);
            byte[] dec_key = ntruDecCipher.ExtractSecret(generatedCT);

            // Check decapsulation secret
            Assert.True(ntruPParameters.DefaultKeySize == dec_key.Length * 8);
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), $"{path} {count}: kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, secret, 0, secret.Length), $"{path} {count}: kem_dec key");
        }

        /// <summary>
        /// Reproduces the reference implementation's pattern of random-byte requests, so that the KATs' generator
        /// yields the same bytes for the engine as it did for the reference.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The KAT files (the NTRU Prime submission's own, generated with NIST's PQCgenKAT harness) record a seed
        /// per vector, not the random bytes. <see cref="NistSecureRandom"/> re-creates NIST's AES-256 CTR DRBG from
        /// that seed, and the bytes it returns depend on how they are requested, not just how many: each call
        /// produces whole 16-byte blocks, returns the bytes asked for, discards the rest of the last block and then
        /// re-keys. One call for 8 bytes therefore differs from two calls for 4.
        /// </para>
        /// <para>
        /// The reference draws the p uint32s behind each random small or short polynomial (Small_random,
        /// Short_random) by p separate 4-byte calls (urandom32). The engine makes one 4p-byte call instead, which is
        /// several times faster with a typical generator; this wrapper splits that call back into the reference's
        /// p 4-byte calls. Every other request passes through unchanged. They are recognised by length alone: the
        /// engine's other requests are 32 bytes (NTRU LPRime seeds and inputs) or (p + 3) / 4 bytes (SNTRU Prime's
        /// rho), never 4p.
        /// </para>
        /// <para>
        /// Where spans are available the engine requests the uint32s as a span. Like any SecureRandom constructed
        /// without a generator, this one serves span requests through <see cref="NextBytes(byte[])"/>, so they are
        /// split too.
        /// </para>
        /// <para>
        /// Only replaying the KATs needs this. Otherwise the engine's single call is just as good as the reference's
        /// many: the bytes differ, but they are equally random.
        /// </para>
        /// </remarks>
        private sealed class ReferenceDrawsRandom
            : SecureRandom
        {
            private readonly SecureRandom m_random;
            private readonly int m_drawsLength;

            internal ReferenceDrawsRandom(SecureRandom random, int p)
                : base(null)
            {
                m_random = random;
                m_drawsLength = 4 * p;
            }

            public override void NextBytes(byte[] buf) => NextBytes(buf, 0, buf.Length);

            public override void NextBytes(byte[] buf, int off, int len)
            {
                if (len != m_drawsLength)
                {
                    m_random.NextBytes(buf, off, len);
                    return;
                }

                for (int i = 0; i < len; i += 4)
                {
                    m_random.NextBytes(buf, off + i, 4);
                }
            }
        }
    }
}
