using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class GeneralNameTest
    {
        private static readonly byte[] ipv4 = Hex.Decode("87040a090800");
        private static readonly byte[] ipv4WithMask1 = Hex.Decode("87080a090800ffffff00");
        private static readonly byte[] ipv4WithMask2 = Hex.Decode("87080a090800ffff8000");
        private static readonly byte[] ipv4WithMask3 = Hex.Decode("87080a090800ffffc000");

        private static readonly byte[] ipv6a = Hex.Decode("871020010db885a308d313198a2e03707334");
        private static readonly byte[] ipv6b = Hex.Decode("871020010db885a3000013198a2e03707334");
        private static readonly byte[] ipv6c = Hex.Decode("871000000000000000000000000000000001");
        private static readonly byte[] ipv6d = Hex.Decode("871020010db885a3000000008a2e03707334");
        private static readonly byte[] ipv6e = Hex.Decode("871020010db885a3000000008a2e0a090800");
        private static readonly byte[] ipv6f = Hex.Decode("872020010db885a3000000008a2e0a090800ffffffffffff00000000000000000000");
        private static readonly byte[] ipv6g = Hex.Decode("872020010db885a3000000008a2e0a090800ffffffffffffffffffffffffffffffff");
        private static readonly byte[] ipv6h = Hex.Decode("872020010db885a300000000000000000000ffffffffffff00000000000000000000");
        private static readonly byte[] ipv6i = Hex.Decode("872020010db885a300000000000000000000fffffffffffe00000000000000000000");
        private static readonly byte[] ipv6j = Hex.Decode("872020010db885a300000000000000000000ffffffffffff80000000000000000000");

        /// <summary>Regression test for the EdiPartyName ASN.1 type.</summary>
        /// <remarks>
        /// RFC 5280 sec. 4.2.1.6:
        /// <code>
        /// EDIPartyName::= SEQUENCE {
        ///      nameAssigner   [0] DirectoryString OPTIONAL,
        ///      partyName      [1] DirectoryString }
        /// </code>
        /// Both tags are explicit, despite the module's IMPLICIT TAGS, because DirectoryString is a CHOICE and X.680
        /// does not permit implicitly tagging one. The decoder had this right but ToAsn1Object emitted the
        /// DirectoryStrings bare, so an EDIPartyName built through the constructor could not parse its own encoding,
        /// and neither could GeneralName - which since the type was added validates the ediPartyName alternative
        /// through it (github bc-java #2380).
        /// </remarks>
        [Test]
        public void EdiPartyNameType()
        {
            // SEQUENCE { [0] { UTF8String "assigner" }, [1] { UTF8String "party" } }
            byte[] expected = Hex.Decode("3015a00a0c0861737369676e6572a1070c057061727479");

            EdiPartyName both = new EdiPartyName(new DirectoryString("assigner"), new DirectoryString("party"));
            Assert.That(Arrays.AreEqual(expected, both.GetEncoded(Asn1Encodable.Der)),
                "EDIPartyName encoding not as RFC 5280");

            EdiPartyName decoded = EdiPartyName.GetInstance(both.GetEncoded(Asn1Encodable.Der));
            Assert.AreEqual("assigner", decoded.NameAssigner.GetString());
            Assert.AreEqual("party", decoded.PartyName.GetString());

            // nameAssigner is OPTIONAL; partyName keeps its [1] tag either way
            byte[] partyOnly = Hex.Decode("3009a1070c057061727479");
            EdiPartyName one = new EdiPartyName(null, new DirectoryString("party"));
            Assert.That(Arrays.AreEqual(partyOnly, one.GetEncoded(Asn1Encodable.Der)),
                "optional nameAssigner encoding wrong");

            EdiPartyName decodedOne = EdiPartyName.GetInstance(one.GetEncoded(Asn1Encodable.Der));
            Assert.Null(decodedOne.NameAssigner, "nameAssigner should be absent");
            Assert.AreEqual("party", decodedOne.PartyName.GetString());

            // and the GeneralName path that validates the alternative
            GeneralName gn = GeneralName.GetInstance(
                new DerTaggedObject(false, GeneralName.EdiPartyName, Asn1Object.FromByteArray(expected)));
            Assert.AreEqual(GeneralName.EdiPartyName, gn.TagNo);

            // an untagged sequence remains a decode failure - the type is not read leniently
            try
            {
                EdiPartyName.GetInstance(Hex.Decode("30110c0861737369676e65720c057061727479"));
                Assert.Fail("untagged EDIPartyName accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        [Test]
        public void IPv4()
        {
            CheckIPAddressEncoding("10.9.8.0", ipv4, "ipv4 encoding failed");
            CheckIPAddressEncoding("10.9.8.0/255.255.255.0", ipv4WithMask1, "ipv4 with netmask 1 encoding failed");
            CheckIPAddressEncoding("10.9.8.0/24", ipv4WithMask1, "ipv4 with netmask 2 encoding failed");
            CheckIPAddressEncoding("10.9.8.0/255.255.128.0", ipv4WithMask2, "ipv4 with netmask 3a encoding failed");
            CheckIPAddressEncoding("10.9.8.0/17", ipv4WithMask2, "ipv4 with netmask 3b encoding failed");
            CheckIPAddressEncoding("10.9.8.0/255.255.192.0", ipv4WithMask3, "ipv4 with netmask 3a encoding failed");
            CheckIPAddressEncoding("10.9.8.0/18", ipv4WithMask3, "ipv4 with netmask 3b encoding failed");
        }

        [Test]
        public void IPv6()
        {
            CheckIPAddressEncoding("2001:0db8:85a3:08d3:1319:8a2e:0370:7334", ipv6a, "ipv6a failed");
            CheckIPAddressEncoding("2001:0db8:85a3::1319:8a2e:0370:7334", ipv6b, "ipv6b failed");
            CheckIPAddressEncoding("::1", ipv6c, "ipv6c failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:0370:7334", ipv6d, "ipv6d failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:10.9.8.0", ipv6e, "ipv6e failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:10.9.8.0/ffff:ffff:ffff::0000", ipv6f, "ipv6f failed");
            CheckIPAddressEncoding("2001:0db8:85a3::8a2e:10.9.8.0/128", ipv6g, "ipv6g failed");
            CheckIPAddressEncoding("2001:0db8:85a3::/48", ipv6h, "ipv6h failed");
            CheckIPAddressEncoding("2001:0db8:85a3::/47", ipv6i, "ipv6i failed");
            CheckIPAddressEncoding("2001:0db8:85a3::/49", ipv6j, "ipv6j failed");
        }

        private static void CheckIPAddressEncoding(string ipAddress, byte[] expectedEncoding, string message)
        {
            var nm = new GeneralName(GeneralName.IPAddress, ipAddress);
            Assert.That(Arrays.AreEqual(expectedEncoding, nm.GetEncoded()), message);
        }
    }
}
