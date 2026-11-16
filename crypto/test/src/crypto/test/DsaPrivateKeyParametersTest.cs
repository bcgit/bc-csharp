using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class DsaPrivateKeyParametersTest
    {
        // RFC 6979 A.2.1
        private static readonly DsaParameters Parameters = new DsaParameters(
            new BigInteger("86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447" +
                           "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88" +
                           "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C" +
                           "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779", 16),
            new BigInteger("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16),
            new BigInteger("07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D" +
                           "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD" +
                           "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4" +
                           "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD", 16));

        private static BigInteger Q => Parameters.Q;

        [Test]
        public void AcceptsRange()
        {
            Assert.AreEqual(BigInteger.One, new DsaPrivateKeyParameters(BigInteger.One, Parameters).X);

            BigInteger qMinusOne = Q.Subtract(BigInteger.One);
            Assert.AreEqual(qMinusOne, new DsaPrivateKeyParameters(qMinusOne, Parameters).X);
        }

        /// <summary>
        /// FIPS 186-4 sec. 4.1: x is in [1, q-1].
        /// </summary>
        [Test]
        public void RejectsOutOfRange()
        {
            BigInteger[] invalid = { BigInteger.Zero, BigInteger.One.Negate(), Q, Q.Add(BigInteger.One) };

            foreach (BigInteger x in invalid)
            {
                Assert.Throws<ArgumentException>(() => new DsaPrivateKeyParameters(x, Parameters), x.ToString(16));
            }
        }

        [Test]
        public void NullParametersUnchecked()
        {
            Assert.AreEqual(Q, new DsaPrivateKeyParameters(Q, null).X);
        }
    }
}
