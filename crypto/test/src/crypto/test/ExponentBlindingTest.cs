using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// Private exponents are blinded with a random multiple of the group order before the variable-time ModPow. The
    /// blinding multiple is the only single-byte draw these paths make, so counting such draws shows the blinding
    /// ran; the results must be unchanged.
    /// </summary>
    [TestFixture]
    public class ExponentBlindingTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly ElGamalParameters ElGamalParams = new ElGamalParameters(
            new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e3" +
                           "1db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16),
            new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee" +
                           "5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16));

        [Test]
        public void Gost3410_94()
        {
            var kpGen = new Gost3410KeyPairGenerator();
            kpGen.Init(new Gost3410KeyGenerationParameters(Random, CryptoProObjectIdentifiers.GostR3410x94CryptoProA));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            byte[] digest = RandomDigest(32);

            var counting = new CountingRandom();
            var signer = new Gost3410Signer();
            signer.Init(true, new ParametersWithRandom(kp.Private, counting));
            BigInteger[] sig = signer.GenerateSignature(digest);
            Assert.AreEqual(1, counting.Count, "blinding draws");

            var verifier = new Gost3410Signer();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(verifier.VerifySignature(digest, sig[0], sig[1]));
        }

        [Test]
        public void ElGamal()
        {
            var kpGen = new ElGamalKeyPairGenerator();
            kpGen.Init(new ElGamalKeyGenerationParameters(Random, ElGamalParams));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            var enc = new ElGamalEngine();
            enc.Init(true, new ParametersWithRandom(kp.Public, Random));
            byte[] plain = RandomDigest(enc.GetInputBlockSize());
            plain[0] |= 0x01; // no leading zero, so the decryption round-trips byte for byte
            byte[] cipherText = enc.ProcessBlock(plain, 0, plain.Length);

            var counting = new CountingRandom();
            var dec = new ElGamalEngine();
            dec.Init(false, new ParametersWithRandom(kp.Private, counting));
            byte[] recovered = dec.ProcessBlock(cipherText, 0, cipherText.Length);
            Assert.AreEqual(1, counting.Count, "blinding draws");
            Assert.AreEqual(plain, recovered);
        }

        private static byte[] RandomDigest(int length)
        {
            byte[] digest = new byte[length];
            Random.NextBytes(digest);
            return digest;
        }

        /// <summary>
        /// Counts blinding draws only: the blinding multiple is seven bits, so it is the only single-byte request
        /// these paths make.
        /// </summary>
        private sealed class CountingRandom
            : SecureRandom
        {
            internal int Count;

            public override void NextBytes(byte[] buf)
            {
                if (buf.Length == 1)
                {
                    ++Count;
                }
                base.NextBytes(buf);
            }

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void NextBytes(Span<byte> buffer)
            {
                if (buffer.Length == 1)
                {
                    ++Count;
                }
                base.NextBytes(buffer);
            }
#endif
        }
    }
}
