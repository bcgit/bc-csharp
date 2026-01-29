
using NUnit.Framework;

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
        private readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void Test128Extra()
        {
            byte[] seed = Hex.Decode("000102030405060708090a0b0c0d0e0f10111213");
            byte[] partyAInfo = Hex.Decode("0123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201"
                + "0123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201");
            byte[] result = Hex.Decode("48950c46e0530075403cce72889604e0");

            var kdf = new DHKekGenerator(new Sha1Digest());
            var kdfParameters = new DHKdfParameters(PkcsObjectIdentifiers.IdAlgCmsRC2Wrap, 128, seed, partyAInfo);

            CheckMask(nameof(Test128Extra), kdf, kdfParameters, result);
        }

        [Test]
        public void Test192()
        {
            byte[] seed = Hex.Decode("000102030405060708090a0b0c0d0e0f10111213");
            byte[] result = Hex.Decode("a09661392376f7044d9052a397883246b67f5f1ef63eb5fb");

            var kdf = new DHKekGenerator(new Sha1Digest());
            var kdfParameters = new DHKdfParameters(PkcsObjectIdentifiers.IdAlgCms3DesWrap, 192, seed);

            CheckMask(nameof(Test192), kdf, kdfParameters, result);
        }

        private void CheckMask(string name, IDerivationFunction kdf, IDerivationParameters parameters,
            byte[] result)
        {
            byte[] data = SecureRandom.GetNextBytes(Random, result.Length);

            kdf.Init(parameters);
            kdf.GenerateBytes(data, 0, data.Length);

            Assert.True(Arrays.AreEqual(result, data), "DHKekGenerator failed generator test " + name);
        }
    }
}
