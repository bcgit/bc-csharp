using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
	public class GeneralNameTest
	{
		private static readonly byte[] ipv4 = Hex.Decode("87040a090800");
        private static readonly byte[] ipv4WithMask24 = Hex.Decode("87080a090800ffffff00");
        private static readonly byte[] ipv4WithMask14 = Hex.Decode("87080a090800fffc0000");

		private static readonly byte[] ipv6a = Hex.Decode("871020010db885a308d313198a2e03707334");
		private static readonly byte[] ipv6b = Hex.Decode("871020010db885a3000013198a2e03707334");
		private static readonly byte[] ipv6c = Hex.Decode("871000000000000000000000000000000001");
		private static readonly byte[] ipv6d = Hex.Decode("871020010db885a3000000008a2e03707334");
		private static readonly byte[] ipv6e = Hex.Decode("871020010db885a3000000008a2e0a090800");
		private static readonly byte[] ipv6f = Hex.Decode("872020010db885a3000000008a2e0a090800ffffffffffff00000000000000000000");
		private static readonly byte[] ipv6g = Hex.Decode("872020010db885a3000000008a2e0a090800ffffffffffffffffffffffffffffffff");
		private static readonly byte[] ipv6h = Hex.Decode("872020010db885a300000000000000000000ffffffffffff00000000000000000000");

		[Test]
		public void TestIPv4()
		{
			CheckIPAddressEncoding("10.9.8.0", ipv4, "ipv4 encoding failed");
            CheckIPAddressEncoding("10.9.8.0/255.255.255.0", ipv4WithMask24, "ipv4 with netmask 1 encoding (24bit) failed");
            CheckIPAddressEncoding("10.9.8.0/24", ipv4WithMask24, "ipv4 with netmask 2 encoding (24bit) failed");
            CheckIPAddressEncoding("10.9.8.0/255.252.0.0", ipv4WithMask14, "ipv4 with netmask 1 encoding (14bit) failed");
            CheckIPAddressEncoding("10.9.8.0/14", ipv4WithMask14, "ipv4 with netmask 2 encoding (14bit) failed");
        }

		[Test]
        public void TestIPv6()
		{
			GeneralName nm;
            CheckIPAddressEncoding("2001:0db8:85a3:08d3:1319:8a2e:0370:7334", ipv6a, "ipv6a failed");
            CheckIPAddressEncoding("2001:0db8:85a3::1319:8a2e:0370:7334", ipv6b, "ipv6b failed");
            CheckIPAddressEncoding("::1", ipv6c, "ipv6c failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:0370:7334", ipv6d, "ipv6d failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:10.9.8.0", ipv6e, "ipv6e failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:10.9.8.0/ffff:ffff:ffff::0000", ipv6f, "ipv6f failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:10.9.8.0/128", ipv6g, "ipv6g failed");
            CheckIPAddressEncoding("2001:0db8:85a3::/48", ipv6h, "ipv6h failed");
		}

        private static void CheckIPAddressEncoding(string inputIPv4, byte[] expectedEncoding, string message)
        {
            var nm = new GeneralName(GeneralName.IPAddress, inputIPv4);
            Assert.IsTrue(Arrays.AreEqual(expectedEncoding, nm.GetEncoded()), message);
        }
    }
}
