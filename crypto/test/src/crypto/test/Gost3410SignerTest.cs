using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class Gost3410SignerTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static IEnumerable<TestCaseData> NamedParameters()
        {
            foreach (string name in Gost3410NamedParameters.Names)
            {
                yield return new TestCaseData(name).SetArgDisplayNames(name);
            }
        }

        /// <summary>
        /// GOST R 34.10-94 verification requires 0 &lt; r &lt; q and 0 &lt; s &lt; q. With s = 0 accepted, anyone can
        /// forge a signature over a chosen digest: for random t, r = (y^t mod p) mod q and m = -r * t^-1 mod q give
        /// z1 = 0 and z2 = t, so u = r.
        /// </summary>
        [TestCaseSource(nameof(NamedParameters))]
        public void RejectsZeroS(string paramSetName)
        {
            var kpGen = new Gost3410KeyPairGenerator();
            kpGen.Init(new Gost3410KeyGenerationParameters(Random, Gost3410NamedParameters.GetOid(paramSetName)));
            var publicKey = (Gost3410PublicKeyParameters)kpGen.GenerateKeyPair().Public;
            BigInteger p = publicKey.Parameters.P, q = publicKey.Parameters.Q;

            BigInteger t, r;
            do
            {
                t = BigIntegers.CreateRandomInRange(BigInteger.One, q.Subtract(BigInteger.One), Random);
                r = publicKey.Y.ModPow(t, p).Mod(q);
            }
            while (r.SignValue == 0);

            BigInteger m = q.Subtract(r).Multiply(t.ModInverse(q)).Mod(q);
            byte[] digest = Arrays.Reverse(BigIntegers.AsUnsignedByteArray(32, m)); // little-endian

            var verifier = new Gost3410Signer();
            verifier.Init(false, publicKey);
            Assert.IsFalse(verifier.VerifySignature(digest, r, BigInteger.Zero), "forged (r, 0) verifies");
        }

        /// <summary>
        /// A zero nonce must be redrawn: it gives r = 1 and s = x * r, which is the private key.
        /// </summary>
        [Test]
        public void RedrawsZeroNonce()
        {
            var kpGen = new Gost3410KeyPairGenerator();
            kpGen.Init(new Gost3410KeyGenerationParameters(Random, CryptoProObjectIdentifiers.GostR3410x94CryptoProA));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            var privateKey = (Gost3410PrivateKeyParameters)kp.Private;
            BigInteger p = privateKey.Parameters.P, q = privateKey.Parameters.Q, a = privateKey.Parameters.A;
            int len = (q.BitLength + 7) / 8;

            byte[] digest = new byte[len];
            Random.NextBytes(digest);
            BigInteger m = new BigInteger(1, digest, bigEndian: false).Mod(q);

            BigInteger k = BigIntegers.CreateRandomInRange(BigInteger.One, q.Subtract(BigInteger.One), Random);
            // zero nonce, its replacement, then one byte for the exponent blinding
            var random = FixedSecureRandom.From(new byte[len], BigIntegers.AsUnsignedByteArray(len, k), new byte[1]);

            var signer = new Gost3410Signer();
            signer.Init(true, new ParametersWithRandom(privateKey, random));
            BigInteger[] sig = signer.GenerateSignature(digest);

            Assert.IsTrue(random.IsExhausted, "zero nonce was not redrawn");

            BigInteger r = a.ModPow(k, p).Mod(q);
            BigInteger s = k.Multiply(m).Add(privateKey.X.Multiply(r)).Mod(q);
            Assert.AreEqual(r, sig[0]);
            Assert.AreEqual(s, sig[1]);
        }

        [Test]
        public void RejectsZeroR()
        {
            var kpGen = new Gost3410KeyPairGenerator();
            kpGen.Init(new Gost3410KeyGenerationParameters(Random, CryptoProObjectIdentifiers.GostR3410x94CryptoProA));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            byte[] digest = new byte[32];
            Random.NextBytes(digest);

            var signer = new Gost3410Signer();
            signer.Init(true, new ParametersWithRandom(kp.Private, Random));
            BigInteger[] sig = signer.GenerateSignature(digest);

            var verifier = new Gost3410Signer();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(verifier.VerifySignature(digest, sig[0], sig[1]));
            Assert.IsFalse(verifier.VerifySignature(digest, BigInteger.Zero, sig[1]));
        }
    }
}
