using System.IO;

using NUnit.Framework;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Regression test for the unbounded subpacket allocation (CVE-2026-3505 sibling): a crafted
    /// long-length header must be rejected before the body byte[] is allocated, capping a pre-auth
    /// multi-gigabyte allocation DoS. Mirrors bc-java commit a43c40dc12.
    /// </summary>
    [TestFixture]
    public class SubpacketLengthLimitTest
    {
        [Test]
        public void UserAttributeSubpacketOverCapIsRejected()
        {
            // A full body is supplied so that, without the cap, the parser would allocate and read
            // it successfully -- i.e. the cap is the only reason it is rejected.
            byte[] packet = BuildSubpacket(UserAttributeSubpacketsParser.MaxSubpacketLength + 2, tag: 100);

            var parser = new UserAttributeSubpacketsParser(new MemoryStream(packet, writable: false));

            Assert.Throws<MalformedPacketException>(() => parser.ReadPacket());
        }

        [Test]
        public void SignatureSubpacketOverCapIsRejected()
        {
            byte[] packet = BuildSubpacket(SignatureSubpacketsParser.MaxSubpacketLength + 2, tag: 100);

            var parser = new SignatureSubpacketsParser(new MemoryStream(packet, writable: false));

            Assert.Throws<MalformedPacketException>(() => parser.ReadPacket());
        }

        // Build a new-format subpacket: 5-octet length header (0xFF + uint32 big-endian), one tag
        // octet, then bodyLen-1 body octets (left zero).
        private static byte[] BuildSubpacket(int bodyLen, byte tag)
        {
            byte[] result = new byte[5 + bodyLen];
            result[0] = 0xFF;
            result[1] = (byte)(bodyLen >> 24);
            result[2] = (byte)(bodyLen >> 16);
            result[3] = (byte)(bodyLen >> 8);
            result[4] = (byte)bodyLen;
            result[5] = tag;
            return result;
        }
    }
}
