using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
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
