using NUnit.Framework;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Test cases for the DefaultXmssOid class.
    /// </summary>
    [TestFixture]
    public class XmssOidTests
    {
        [Test]
        public void TestXmssOidException1()
        {
            DefaultXmssOid xmssOid = DefaultXmssOid.Lookup("SHA-256", 32, 16, 67, -1);
            Assert.IsNull(xmssOid);
        }

        [Test]
        public void TestXmssOidException2()
        {
            DefaultXmssOid xmssOid = DefaultXmssOid.Lookup("SHA-256", 32, 16, 67, 8);
            Assert.IsNull(xmssOid);
        }

        [Test]
        public void TestXmssOidException3()
        {
            DefaultXmssOid xmssOid = DefaultXmssOid.Lookup("SHA-256", 32, 4, 67, 10);
            Assert.IsNull(xmssOid);
        }

        [Test]
        public void TestXmssOid()
        {
            DefaultXmssOid xmssOid = DefaultXmssOid.Lookup("SHA-256", 32, 16, 67, 10);
            Assert.AreEqual(0x00000001, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_10_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-256", 32, 16, 67, 16);
            Assert.AreEqual(0x00000002, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_16_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-256", 32, 16, 67, 20);
            Assert.AreEqual(0x00000003, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_20_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-512", 64, 16, 131, 10);
            Assert.AreEqual(0x00000004, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_10_512", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-512", 64, 16, 131, 16);
            Assert.AreEqual(0x00000005, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_16_512", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-512", 64, 16, 131, 20);
            Assert.AreEqual(0x00000006, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_20_512", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE128", 32, 16, 67, 10);
            Assert.AreEqual(0x00000007, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE_10_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE128", 32, 16, 67, 16);
            Assert.AreEqual(0x00000008, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE_16_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE128", 32, 16, 67, 20);
            Assert.AreEqual(0x00000009, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE_20_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256", 64, 16, 131, 10);
            Assert.AreEqual(0x0000000a, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE_10_512", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256", 64, 16, 131, 16);
            Assert.AreEqual(0x0000000b, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE_16_512", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256", 64, 16, 131, 20);
            Assert.AreEqual(0x0000000c, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE_20_512", xmssOid.ToString());
        }

        [Test]
        public void TestXmssOidSP800208()
        {
            // SP 800-208: SHA-256/192 (n=24)
            DefaultXmssOid xmssOid = DefaultXmssOid.Lookup("SHA-256", 24, 16, 51, 10);
            Assert.AreEqual(0x0000000d, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_10_192", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-256", 24, 16, 51, 16);
            Assert.AreEqual(0x0000000e, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_16_192", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHA-256", 24, 16, 51, 20);
            Assert.AreEqual(0x0000000f, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHA2_20_192", xmssOid.ToString());

            // SP 800-208: SHAKE256/256 (n=32)
            xmssOid = DefaultXmssOid.Lookup("SHAKE256-LEN", 32, 16, 67, 10);
            Assert.AreEqual(0x00000010, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE256_10_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256-LEN", 32, 16, 67, 16);
            Assert.AreEqual(0x00000011, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE256_16_256", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256-LEN", 32, 16, 67, 20);
            Assert.AreEqual(0x00000012, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE256_20_256", xmssOid.ToString());

            // SP 800-208: SHAKE256/192 (n=24)
            xmssOid = DefaultXmssOid.Lookup("SHAKE256-LEN", 24, 16, 51, 10);
            Assert.AreEqual(0x00000013, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE256_10_192", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256-LEN", 24, 16, 51, 16);
            Assert.AreEqual(0x00000014, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE256_16_192", xmssOid.ToString());
            xmssOid = DefaultXmssOid.Lookup("SHAKE256-LEN", 24, 16, 51, 20);
            Assert.AreEqual(0x00000015, xmssOid.Oid);
            Assert.AreEqual("XMSS_SHAKE256_20_192", xmssOid.ToString());
        }

        // TestXmssParamsLookupByOidSP800208: deferred to the task that adds XmssParameters (LookupByOid).
    }
}
