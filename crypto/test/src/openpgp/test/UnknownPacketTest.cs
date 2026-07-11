using System;
using System.IO;
using System.Net.Sockets;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class UnknownPacketTest
    {
        [Test]
        public void UnknownCriticalPacket()
        {
            PacketTag tag = (PacketTag)39; // within critical range
            byte[] contents = new byte[]{ 0x50, 0x47, 0x50, 0x61, 0x69, 0x6e, 0x6c, 0x65, 0x73, 0x73 };
            MemoryStream bIn = new MemoryStream(contents, false);
            BcpgInputStream bcIn = new BcpgInputStream(bIn);
            UnknownPacket packet = new UnknownPacket(tag, bcIn);

            Assert.True(packet.IsCritical);
            ImplTestPacketEncoding(tag, contents, packet);
        }

        [Test]
        public void UnknownNonCriticalPacket()
        {
            PacketTag tag = (PacketTag)44; // within non-critical range
            byte[] contents = new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
            MemoryStream bIn = new MemoryStream(contents, false);
            BcpgInputStream bcIn = new BcpgInputStream(bIn);
            UnknownPacket packet = new UnknownPacket(tag, bcIn);

            Assert.False(packet.IsCritical);
            ImplTestPacketEncoding(tag, contents, packet);
        }

        [Test]
        public void ParseNonCriticalPacket()
        {
            PacketTag tag = (PacketTag)44; // within non-critical range
            string encodedCriticalPacket = "ec0e4f70656e50475020726f636b7321"; // Tag 44
            MemoryStream bIn = new MemoryStream(Hex.Decode(encodedCriticalPacket), false);

            PgpObjectFactory objectFactory = new PgpObjectFactory(bIn);
            PgpUnknown unknown = (PgpUnknown)objectFactory.NextPgpObject();
            Assert.AreEqual(tag, unknown.PacketTag);
            Assert.False(unknown.IsCritical);
        }

        [Test]
        public void ParseCriticalPacketWithoutThrowing()
        {
            PacketTag tag = (PacketTag)36; // within critical range
            string encodedCriticalPacket = "e40e4f70656e50475020726f636b7321"; // Tag 36
            MemoryStream bIn = new MemoryStream(Hex.Decode(encodedCriticalPacket), false);

            PgpObjectFactory objectFactory = new PgpObjectFactory(bIn);
            PgpUnknown unknown = (PgpUnknown)objectFactory.NextPgpObject();
            Assert.AreEqual(tag, unknown.PacketTag);
            Assert.True(unknown.IsCritical);
        }

        [Test]
        public void ParseCriticalPacketWithThrowing()
        {
            string encodedCriticalPacket = "e40e4f70656e50475020726f636b7321"; // Tag 36
            MemoryStream bIn = new MemoryStream(Hex.Decode(encodedCriticalPacket), false);

            // Enable exception throwing for unknown critical packets
            PgpObjectFactory objectFactory = new PgpObjectFactory(bIn)
                .SetThrowForUnknownCriticalPackets(true);
            try
            {
                objectFactory.NextPgpObject();
                Assert.Fail("Expected IOException, but nothing was thrown");
            }
            catch (IOException)
            {
                // expected
            }
        }

        private int EncodeTag(PacketTag tag)
        {
            int hdr = 0x80;
            hdr |= 0x40 | (int)tag;
            return hdr & 0xFF;
        }

        private void ImplTestPacketEncoding(PacketTag tag, byte[] contents, UnknownPacket packet)
        {
            byte[] encoded = packet.GetEncoded();

            int hdr = EncodeTag(tag);
            Assert.AreEqual(hdr, encoded[0]);
            Assert.AreEqual(contents.Length, encoded[1]);
            for (int i = 0; i < contents.Length; i++)
            {
                Assert.AreEqual(encoded[i + 2], contents[i]);
            }
        }
    }
}
