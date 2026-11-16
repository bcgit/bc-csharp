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
    public class ECGost3410SignerTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        /// <summary>
        /// The nonce is drawn with the bit length of n, so a draw at or past n must be redrawn rather than folded by
        /// the reduction that follows. On CryptoPro-C (n ~ 0.61 * 2^256) folding made about 39% of nonces land in
        /// [0, 0.65 n), doubling their likelihood.
        /// </summary>
        [Test]
        public void RedrawsNonceAtOrPastOrder()
        {
            var domain = new ECDomainParameters(
                ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProC));
            BigInteger n = domain.N;
            int len = (n.BitLength + 7) / 8;

            var kpGen = new ECKeyPairGenerator();
            kpGen.Init(new ECKeyGenerationParameters(domain, Random));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            BigInteger d = ((ECPrivateKeyParameters)kp.Private).D;

            byte[] digest = new byte[len];
            Random.NextBytes(digest);
            BigInteger e = new BigInteger(1, digest, bigEndian: false).Mod(n);

            byte[] tooLarge = new byte[len];
            Arrays.Fill(tooLarge, 0xFF); // 2^256 - 1, at least n
            BigInteger k = BigIntegers.CreateRandomInRange(BigInteger.One, n.Subtract(BigInteger.One), Random);

            var random = FixedSecureRandom.From(tooLarge, BigIntegers.AsUnsignedByteArray(len, k));

            var signer = new ECGost3410Signer();
            signer.Init(true, new ParametersWithRandom(kp.Private, random));
            BigInteger[] sig = signer.GenerateSignature(digest);

            Assert.IsTrue(random.IsExhausted, "nonce at the order was not redrawn");

            BigInteger r = domain.G.Multiply(k).Normalize().AffineXCoord.ToBigInteger().Mod(n);
            BigInteger s = k.Multiply(e).Add(d.Multiply(r)).Mod(n);
            Assert.AreEqual(r, sig[0]);
            Assert.AreEqual(s, sig[1]);
        }
    }
}
