using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class ElGamalTest
    {
        private static readonly BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        private static readonly BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        private static readonly BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
        private static readonly BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

        private static readonly BigInteger g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
        private static readonly BigInteger p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

        [Test]
        public void Enc512()
        {
            ImplTestEnc(512, 0, g512, p512);
            ImplTestEnc(512, 64, g512, p512);
        }

        [Test]
        public void Enc768()
        {
            ImplTestEnc(768, 0, g768, p768);
            ImplTestEnc(768, 128, g768, p768);
        }

        [Test]
        public void Enc1024()
        {
            ImplTestEnc(1024, 0, g1024, p1024);
        }

        [Test]
        public void Generation258()
        {
            ImplTestGeneration(258);
        }

        [Test]
        public void InitCheck()
        {
            try
            {
                new ElGamalEngine().ProcessBlock(new byte[]{ 1 }, 0, 1);
                Assert.Fail("failed initialisation check");
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }

        private static readonly TestCaseData[] BaseBlindingCases =
        {
            new TestCaseData(new ElGamalParameters(p768, g768, 0)).SetArgDisplayNames("full-size x"),
            new TestCaseData(new ElGamalParameters(p768, g768, 256)).SetArgDisplayNames("short x"),
        };

        /// <summary>
        /// The sender chooses gamma, which decryption raises to the private key, so that base is blinded with a
        /// random value. The plaintext must be unchanged, and the blinding must draw on the random given to Init.
        /// </summary>
        [TestCaseSource(nameof(BaseBlindingCases))]
        public void DecryptionBlindsBase(ElGamalParameters parameters)
        {
            var random = new SecureRandom();
            BigInteger p = parameters.P;

            var kpGen = new ElGamalKeyPairGenerator();
            kpGen.Init(new ElGamalKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            var enc = new ElGamalEngine();
            enc.Init(true, new ParametersWithRandom(kp.Public, random));
            byte[] plain = new byte[enc.GetInputBlockSize()];
            random.NextBytes(plain);
            plain[0] |= 0x01; // no leading zero, so the decryption round-trips byte for byte
            byte[] cipherText = enc.ProcessBlock(plain, 0, plain.Length);

            var counting = new CallCountingRandom();
            var dec = new ElGamalEngine();
            dec.Init(false, new ParametersWithRandom(kp.Private, counting));
            byte[] recovered = dec.ProcessBlock(cipherText, 0, cipherText.Length);
            Assert.Greater(counting.Calls, 0, "blinding draws");
            Assert.AreEqual(plain, recovered);

            // the same as the textbook gamma^(p - 1 - x) * phi
            int half = cipherText.Length / 2;
            BigInteger gamma = new BigInteger(1, cipherText, 0, half);
            BigInteger phi = new BigInteger(1, cipherText, half, half);
            BigInteger x = ((ElGamalPrivateKeyParameters)kp.Private).X;
            BigInteger m = gamma.ModPow(p.Subtract(BigInteger.One).Subtract(x), p).Multiply(phi).Mod(p);
            Assert.AreEqual(m, new BigInteger(1, recovered));
        }

        [Test]
        public void MaliciousCiphertext()
        {
            // ElGamal decryption raises the first ciphertext component (gamma) to the static private key,
            // so an out-of-range or small-order gamma -- or phi -- must be rejected before the modPow;
            // otherwise a peer can mount a small-subgroup confinement attack against a reused decryption
            // key (the class closed for DHAgreement). The DH analogue is DHTest.testMaliciousMessage.
            ElGamalParameters dhParams = new ElGamalParameters(p512, g512, 0);
            ElGamalKeyPairGenerator kpGen = new ElGamalKeyPairGenerator();
            kpGen.Init(new ElGamalKeyGenerationParameters(new SecureRandom(), dhParams));

            ElGamalPrivateKeyParameters pv = (ElGamalPrivateKeyParameters)kpGen.GenerateKeyPair().Private;

            ElGamalEngine e = new ElGamalEngine();
            e.Init(false, pv);

            int half = BigIntegers.GetUnsignedByteLength(p512);

            // weak / out-of-range component values: 0 and 1 (small order / below range), p-1 (order 2)
            // and p (>= range). A well-formed gamma = g^k mod p is always in (1, p-1), so these never
            // arise from a legitimate ciphertext.
            BigInteger[] weakValues = new BigInteger[]
            {
                BigInteger.Zero,
                BigInteger.One,
                p512.Subtract(BigInteger.One),
                p512
            };

            // an in-range component (2 lies in [2, p-2]) used to fill the other half, so each case
            // isolates the component under test.
            byte[] goodHalf = BigIntegers.AsUnsignedByteArray(half, BigInteger.Two);

            foreach (var weakValue in weakValues)
            {
                byte[] weakHalf = BigIntegers.AsUnsignedByteArray(half, weakValue);

                // weak gamma (first half), valid phi (second half)
                CheckRejected(e, weakHalf, goodHalf, "gamma", weakValue);
                // valid gamma (first half), weak phi (second half)
                CheckRejected(e, goodHalf, weakHalf, "phi", weakValue);
            }
        }

        private void ImplTestEnc(int size, int privateValueSize, BigInteger g, BigInteger p)
        {
            ElGamalParameters dhParams = new ElGamalParameters(p, g, privateValueSize);
            ElGamalKeyGenerationParameters ekgParams = new ElGamalKeyGenerationParameters(new SecureRandom(), dhParams);
            ElGamalKeyPairGenerator kpGen = new ElGamalKeyPairGenerator();

            kpGen.Init(ekgParams);

            //
            // generate pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            ElGamalPublicKeyParameters pu = (ElGamalPublicKeyParameters)pair.Public;
            ElGamalPrivateKeyParameters pv = (ElGamalPrivateKeyParameters)pair.Private;

            CheckKeySize(privateValueSize, pv);

            ElGamalEngine e = new ElGamalEngine();

            e.Init(true, pu);

            if (e.GetOutputBlockSize() != size / 4)
            {
                Assert.Fail(size + " GetOutputBlockSize() on encryption failed.");
            }

            byte[] message = Hex.Decode("5468697320697320612074657374");

            byte[] pText = message;
            byte[] cText = e.ProcessBlock(pText, 0, pText.Length);

            e.Init(false, pv);

            if (e.GetOutputBlockSize() != (size / 8) - 1)
            {
                Assert.Fail(size + " GetOutputBlockSize() on decryption failed.");
            }

            pText = e.ProcessBlock(cText, 0, cText.Length);

            if (!Arrays.AreEqual(message, pText))
            {
                Assert.Fail(size + " bit test failed");
            }

            e.Init(true, pu);
            byte[] bytes = new byte[e.GetInputBlockSize() + 2];

            try
            {
                e.ProcessBlock(bytes, 0, bytes.Length);

                Assert.Fail("out of range block not detected");
            }
            catch (DataLengthException)
            {
                // expected
            }

            try
            {
                bytes[0] = (byte)0xff;

                e.ProcessBlock(bytes, 0, bytes.Length - 1);

                Assert.Fail("out of range block not detected");
            }
            catch (DataLengthException)
            {
                // expected
            }

            try
            {
                bytes[0] = (byte)0x7f;

                e.ProcessBlock(bytes, 0, bytes.Length - 1);
            }
            catch (DataLengthException)
            {
                Assert.Fail("in range block failed");
            }
        }

        private void CheckKeySize(int privateValueSize, ElGamalPrivateKeyParameters priv)
        {
            if (privateValueSize != 0)
            {
                if (priv.X.BitLength != privateValueSize)
                {
                    Assert.Fail("limited key check failed for key size " + privateValueSize);
                }
            }
        }

        private void CheckRejected(ElGamalEngine e, byte[] firstHalf, byte[] secondHalf, string which,
            BigInteger value)
        {
            byte[] cText = Arrays.Concatenate(firstHalf, secondHalf);

            try
            {
                e.ProcessBlock(cText, 0, cText.Length);

                Assert.Fail("ElGamal accepted weak " + which + " = " + value);
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        /**
         * this test is can take quiet a while
         *
         * @param size size of key in bits.
         */
        private void ImplTestGeneration(int size)
        {
            ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

            pGen.Init(size, 10, new SecureRandom());

            ElGamalParameters elParams = pGen.GenerateParameters();

            if (elParams.L != 0)
            {
                Assert.Fail("ElGamalParametersGenerator failed to set L to 0 in generated ElGamalParameters");
            }

            ElGamalKeyGenerationParameters ekgParams = new ElGamalKeyGenerationParameters(new SecureRandom(), elParams);

            ElGamalKeyPairGenerator kpGen = new ElGamalKeyPairGenerator();

            kpGen.Init(ekgParams);

            //
            // generate first pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            ElGamalPublicKeyParameters pu = (ElGamalPublicKeyParameters)pair.Public;
            ElGamalPrivateKeyParameters pv = (ElGamalPrivateKeyParameters)pair.Private;

            ElGamalEngine e = new ElGamalEngine();

            e.Init(true, new ParametersWithRandom(pu, new SecureRandom()));

            byte[] message = Hex.Decode("5468697320697320612074657374");

            byte[] pText = message;
            byte[] cText = e.ProcessBlock(pText, 0, pText.Length);

            e.Init(false, pv);

            pText = e.ProcessBlock(cText, 0, cText.Length);

            if (!Arrays.AreEqual(message, pText))
            {
                Assert.Fail("generation test failed");
            }
        }

        private sealed class CallCountingRandom
            : SecureRandom
        {
            internal int Calls;

            public override void NextBytes(byte[] buf)
            {
                ++Calls;
                base.NextBytes(buf);
            }

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void NextBytes(Span<byte> buffer)
            {
                ++Calls;
                base.NextBytes(buffer);
            }
#endif
        }
    }
}
