using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
    * A ciphertext / wrapped-key shorter than the fixed overhead the engine strips
    * must be rejected with an {@link InvalidCipherTextException}, not an escaping
    * {@code NegativeArraySizeException} / {@code ArrayIndexOutOfBoundsException}
    * from the {@code new byte[inLen - overhead]} allocation.
    */
    [TestFixture]
    public class ShortWrapCipherTextTest
    {
        [Test]
        public void SM2()
        {
            BigInteger p = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
            BigInteger a = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
            BigInteger b = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
            BigInteger n = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
            BigInteger gx = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
            BigInteger gy = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

            ECCurve curve = new FpCurve(p, a, b, n, BigInteger.One);
            ECPoint g = curve.CreatePoint(gx, gy);
            ECDomainParameters domainParams = new ECDomainParameters(curve, g, n);

            ECKeyPairGenerator kpg = new ECKeyPairGenerator();
            kpg.Init(new ECKeyGenerationParameters(domainParams,
                new TestRandomBigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16)));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            SM2Engine engine = new SM2Engine();
            engine.Init(false, (ECPrivateKeyParameters)kp.Private);

            // C1 (65) + C3 (32) is 97 octets; anything shorter cannot hold C1 + digest.
            try
            {
                engine.ProcessBlock(new byte[50], 0, 50);
                Assert.Fail("SM2Engine: no exception on short ciphertext");
            }
            catch (InvalidCipherTextException e)
            {
                Assert.AreEqual("data too short", e.Message);
            }
        }

        [Test]
        public void DSTU7624Wrap()
        {
            Dstu7624WrapEngine engine = new Dstu7624WrapEngine(128);
            engine.Init(false, new KeyParameter(new byte[16]));

            try
            {
                engine.Unwrap(new byte[0], 0, 0);
                Assert.Fail("DSTU7624WrapEngine: no exception on empty input");
            }
            catch (InvalidCipherTextException e)
            {
                Assert.AreEqual("unwrap data too short", e.Message);
            }
        }

        [Test]
        public void DesEdeWrap()
        {
            DesEdeWrapEngine engine = new DesEdeWrapEngine();
            engine.Init(false, new KeyParameter(Hex.Decode("0123456789abcdeffedcba987654321089abcdef01234567")));

            try
            {
                engine.Unwrap(new byte[8], 0, 8);
                Assert.Fail("DESedeWrapEngine: no exception on short input");
            }
            catch (InvalidCipherTextException e)
            {
                Assert.AreEqual("unwrap data too short", e.Message);
            }
        }

        [Test]
        public void RC2Wrap()
        {
            RC2WrapEngine engine = new RC2WrapEngine();
            engine.Init(false, new RC2Parameters(new byte[16]));

            try
            {
                engine.Unwrap(new byte[8], 0, 8);
                Assert.Fail("RC2WrapEngine: no exception on short input");
            }
            catch (InvalidCipherTextException e)
            {
                Assert.AreEqual("unwrap data too short", e.Message);
            }
        }
    }
}
