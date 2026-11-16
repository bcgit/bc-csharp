using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Digests;
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

        // RFC 6979 A.2.1
        private static readonly DsaParameters DsaParams = new DsaParameters(
            new BigInteger("86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447" +
                           "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88" +
                           "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C" +
                           "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779", 16),
            new BigInteger("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16),
            new BigInteger("07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D" +
                           "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD" +
                           "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4" +
                           "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD", 16));

        private static readonly ElGamalParameters ElGamalParams = new ElGamalParameters(
            new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e3" +
                           "1db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16),
            new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee" +
                           "5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16));

        [Test]
        public void Dsa()
        {
            AsymmetricCipherKeyPair kp = GenerateDsaKeyPair();
            byte[] digest = RandomDigest(20);

            var counting = new CountingRandom();
            var signer = new DsaSigner();
            signer.Init(true, new ParametersWithRandom(kp.Private, counting));
            BigInteger[] sig = signer.GenerateSignature(digest);
            Assert.AreEqual(1, counting.Count, "blinding draws");

            var verifier = new DsaSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(verifier.VerifySignature(digest, sig[0], sig[1]));
        }

        [Test]
        public void DsaDeterministic()
        {
            AsymmetricCipherKeyPair kp = GenerateDsaKeyPair();
            byte[] digest = RandomDigest(20);

            var counting = new CountingRandom();
            var signer = new DsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
            signer.Init(true, new ParametersWithRandom(kp.Private, counting));
            BigInteger[] sig1 = signer.GenerateSignature(digest);
            BigInteger[] sig2 = signer.GenerateSignature(digest);

            // the nonce draws nothing, but the blinding still does, without disturbing determinism
            Assert.AreEqual(2, counting.Count, "blinding draws");
            Assert.AreEqual(sig1[0], sig2[0]);
            Assert.AreEqual(sig1[1], sig2[1]);

            var verifier = new DsaSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(verifier.VerifySignature(digest, sig1[0], sig1[1]));
        }

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

        private static AsymmetricCipherKeyPair GenerateDsaKeyPair()
        {
            var kpGen = new DsaKeyPairGenerator();
            kpGen.Init(new DsaKeyGenerationParameters(Random, DsaParams));
            return kpGen.GenerateKeyPair();
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
