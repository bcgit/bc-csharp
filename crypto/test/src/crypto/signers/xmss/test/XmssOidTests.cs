using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Test cases for the DefaultXmssOid and DefaultXmssMTOid classes.
    /// </summary>
    /// <remarks>The XMSS^MT methods are not in the Java fixture; they cover the XMSS^MT table the same way.</remarks>
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

        [Test]
        public void TestXmssParamsLookupByOidSP800208()
        {
            // SHA-256/192 (n=24)
            XmssParameters parameters = XmssParameters.LookupByOid(0x0000000d);
            Assert.IsNotNull(parameters);
            Assert.AreEqual(10, parameters.Height);
            Assert.AreEqual(24, parameters.TreeDigestSize);

            // SHAKE256/256 (n=32)
            parameters = XmssParameters.LookupByOid(0x00000010);
            Assert.IsNotNull(parameters);
            Assert.AreEqual(10, parameters.Height);
            Assert.AreEqual(32, parameters.TreeDigestSize);

            // SHAKE256/192 (n=24)
            parameters = XmssParameters.LookupByOid(0x00000013);
            Assert.IsNotNull(parameters);
            Assert.AreEqual(10, parameters.Height);
            Assert.AreEqual(24, parameters.TreeDigestSize);
        }

        /// <summary>
        /// Every RFC 8391 sec. 5.4 and SP 800-208 XMSS^MT identifier looks up a parameter set that carries it back,
        /// so the parameter table and the identifier table agree entry for entry; the identifiers either side of
        /// them look up nothing.
        /// </summary>
        [Test]
        public void TestXmssMTParamsLookupByOid()
        {
            int[] heights = new int[]{ 20, 20, 40, 40, 40, 60, 60, 60 };
            int[] layers = new int[]{ 2, 4, 2, 4, 8, 3, 6, 12 };
            string[] digests = new string[]{ "SHA-256", "SHA-512", "SHAKE128", "SHAKE256", "SHA-256", "SHAKE256-LEN",
                "SHAKE256-LEN" };
            int[] sizes = new int[]{ 32, 64, 32, 64, 24, 32, 24 };

            for (int oid = 1; oid <= 0x38; oid++)
            {
                XmssMTParameters parameters = XmssMTParameters.LookupByOid(oid);
                int family = (oid - 1) / 8, set = (oid - 1) % 8;

                Assert.IsNotNull(parameters, "oid " + oid);
                Assert.AreEqual(oid, parameters.ParameterSetOid, "oid " + oid);
                Assert.AreEqual(heights[set], parameters.Height, "oid " + oid);
                Assert.AreEqual(layers[set], parameters.Layers, "oid " + oid);
                Assert.AreEqual(heights[set] / layers[set], parameters.XmssParameters.Height, "oid " + oid);
                Assert.AreEqual(digests[family], parameters.TreeDigest, "oid " + oid);
                Assert.AreEqual(sizes[family], parameters.TreeDigestSize, "oid " + oid);
                Assert.AreEqual(16, parameters.WinternitzParameter);
                Assert.AreEqual(sizes[family] == 24 ? 51 : sizes[family] == 32 ? 67 : 131, parameters.Len);
            }

            Assert.IsNull(XmssMTParameters.LookupByOid(0));
            Assert.IsNull(XmssMTParameters.LookupByOid(0x39));
        }

        [Test]
        public void TestXmssMTOid()
        {
            DefaultXmssMTOid oid = DefaultXmssMTOid.Lookup("SHA-256", 32, 16, 67, 20, 2);
            Assert.AreEqual(0x00000001, oid.Oid);
            Assert.AreEqual("XMSSMT_SHA2_20/2_256", oid.ToString());
            oid = DefaultXmssMTOid.Lookup("SHAKE256", 64, 16, 131, 60, 12);
            Assert.AreEqual(0x00000020, oid.Oid);
            Assert.AreEqual("XMSSMT_SHAKE_60/12_512", oid.ToString());
            oid = DefaultXmssMTOid.Lookup("SHAKE256-LEN", 24, 16, 51, 60, 12);
            Assert.AreEqual(0x00000038, oid.Oid);
            Assert.AreEqual("XMSSMT_SHAKE256_60/12_192", oid.ToString());

            // a hypertree outside the registered sets has no identifier, and the parameters built for it carry 0
            Assert.IsNull(DefaultXmssMTOid.Lookup("SHA-256", 32, 16, 67, 4, 2));
            Assert.AreEqual(0, new XmssMTParameters(4, 2, new Org.BouncyCastle.Crypto.Digests.Sha256Digest())
                .ParameterSetOid);

            Assert.Throws<System.ArgumentNullException>(() => DefaultXmssMTOid.Lookup(null, 32, 16, 67, 20, 2));
        }
    }
}
