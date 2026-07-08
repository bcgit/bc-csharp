using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.Tests
{
    [TestFixture]
    public class UserAttributeSubpacketsTest
    {
        /// <summary>Regression test for the unbounded user-attribute subpacket allocation.</summary>
        /// <remarks>
        /// A crafted 4-octet length header must be rejected against the absolute MaxSubpacketLength cap before any body
        /// buffer is allocated, rather than relying on the StreamUtilities.FindLimit() hint (which is ~heap-sized for
        /// non-seekable streams used during packet parsing).
        /// </remarks>
        [Test]
        public void ParserHardLimit()
        {
            // A subpacket header declaring a 3 MiB body via the 4-octet length form, with no body.
            int claimed = 3 * 1024 * 1024;
            MemoryStream bOut = new MemoryStream();
            bOut.WriteByte(0xFF);
            bOut.WriteByte((byte)(claimed >> 24));
            bOut.WriteByte((byte)(claimed >> 16));
            bOut.WriteByte((byte)(claimed >> 8));
            bOut.WriteByte((byte)claimed);
            bOut.WriteByte(0x01); // subpacket type octet
            byte[] crafted = bOut.ToArray();

            // NoSeekMemoryStream impedes FindLimit from finding the available length, so it
            // returns ~int.MaxValue -- the same toothless limit the BcpgInputStream parse path sees.
            var parser = new UserAttributeSubpacketsParser(new NoSeekMemoryStream(crafted));

            try
            {
                parser.ReadPacket();
                Assert.Fail("oversized user attribute subpacket length accepted");
            }
            catch (MalformedPacketException e)
            {
                Assert.That(e.Message.Contains("exceeds max user attribute subpacket length"),
                    "unexpected message: " + e.Message);
            }
        }

        private class NoSeekMemoryStream
            : MemoryStream
        {
            internal NoSeekMemoryStream(byte[] buffer)
                : base(buffer, writable: false)
            {
            }

            public override bool CanSeek => false;
        }
    }
}
