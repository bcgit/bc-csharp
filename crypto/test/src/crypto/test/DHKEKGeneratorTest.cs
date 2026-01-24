
using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <remarks>DHKEK Generator tests - from RFC 2631.</remarks>
    [TestFixture]
    public class DHKekGeneratorTest
    {
        private static SecureRandom Random;

        [SetUp]
        public void SetUp()
        {
            Random = new SecureRandom();
        }

        [TearDown]
        public void TearDown()
        {
            Random = null;
        }

        [Test]
        public void Test128Extra()
        {
            byte[] seed2 = Hex.Decode("000102030405060708090a0b0c0d0e0f10111213");
            byte[] partyAInfo = Hex.Decode("0123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201"
                + "0123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201");
            byte[] result2 = Hex.Decode("48950c46e0530075403cce72889604e0");

            var kdf = new DHKekGenerator(new Sha1Digest());
            var kdfParameters = new DHKdfParameters(PkcsObjectIdentifiers.IdAlgCmsRC2Wrap, 128, seed2, partyAInfo);

            CheckMask(nameof(Test128Extra), kdf, kdfParameters, result2);
        }

        [Test]
        public void Test192()
        {
            byte[] seed1 = Hex.Decode("000102030405060708090a0b0c0d0e0f10111213");
            byte[] result1 = Hex.Decode("a09661392376f7044d9052a397883246b67f5f1ef63eb5fb");

            var kdf = new DHKekGenerator(new Sha1Digest());
            var kdfParameters = new DHKdfParameters(PkcsObjectIdentifiers.IdAlgCms3DesWrap, 192, seed1);

            CheckMask(nameof(Test192), kdf, kdfParameters, result1);
        }

        private static void CheckMask(string name, IDerivationFunction kdf, IDerivationParameters parameters,
            byte[] result)
        {
            byte[] data = SecureRandom.GetNextBytes(Random, result.Length);

            kdf.Init(parameters);
            kdf.GenerateBytes(data, 0, data.Length);

            Assert.True(Arrays.AreEqual(result, data), "DHKekGenerator failed generator test " + name);
        }
    }
}
