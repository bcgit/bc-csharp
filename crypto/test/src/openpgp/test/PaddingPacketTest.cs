using NUnit.Framework;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PaddingPacketTest
        : SimpleTest
    {
        public override string Name => "PaddingPacketTest";

        [Test]
        public void PaddingPacketReadFromStreamTest()
        {
            /*
             * Simple padding packet
             * 
             * 0xD5                   Packet tag (0xC0 | 0x15)
             * 0x04                   Length
             * 0x01 0x02 0x03 0x04    Padding content
             */
            byte[] packet = Hex.Decode("D50401020304");
            byte[] expected = Hex.Decode("01020304");

            using (Stream input = new MemoryStream(packet))
            {
                PgpObjectFactory objectFactory = new PgpObjectFactory(input);
                PgpObject obj = objectFactory.NextPgpObject();

                IsTrue(obj is PgpPadding);

                byte[] padding = (obj as PgpPadding).GetPadding();

                IsEquals($"unexpected padding length: expected {expected.Length} got {padding.Length}", padding.Length, expected.Length);
                FailIf($"unexpected padding", !AreEqual(padding, expected));
            }
        }


        [Test]
        public void PaddingPacketReadThreePacketsFromStreamTest()
        {
            byte[] packet = Hex.Decode("D50401020304D503556677D503AABBCC");
            byte[][] expected = new byte[][] {
                Hex.Decode("01020304"),
                Hex.Decode("556677"),
                Hex.Decode("AABBCC")
            };

            using (Stream input = new MemoryStream(packet))
            {
                PgpObjectFactory objectFactory = new PgpObjectFactory(input);

                int i = 0;
                PgpObject obj;
                while ((obj = objectFactory.NextPgpObject()) != null)
                {
                    IsTrue(obj is PgpPadding);
                    byte[] padding = (obj as PgpPadding).GetPadding();

                    IsEquals($"unexpected padding length: expected {expected[i].Length} got {padding.Length}", padding.Length, expected[i].Length);
                    FailIf($"unexpected padding", !AreEqual(padding, expected[i]));
                    ++i;
                }

                IsEquals(i, 3);
            }
        }

        [Test]
        public void PaddingPacketEncodeTest()
        {
            byte[] encoded = Hex.Decode("D50401020304");

            byte[] padding = Hex.Decode("01020304");
            PaddingPacket packet = new PaddingPacket(padding);

            using (MemoryStream output = new MemoryStream())
            {
                BcpgOutputStream bcOut = new BcpgOutputStream(output);
                packet.Encode(bcOut);
                bcOut.Close();

                FailIf("wrong encoding", !AreEqual(output.ToArray(), encoded));
            }
        }

        [Test]
        public void PaddingPacketEncodeThenDecodeTest()
        {
            SecureRandom random = new SecureRandom();
            PaddingPacket packet = new PaddingPacket(32, random);

            using (MemoryStream output = new MemoryStream())
            {
                BcpgOutputStream bcOut = new BcpgOutputStream(output);
                packet.Encode(bcOut);
                bcOut.Close();

                using (Stream input = new MemoryStream(output.ToArray()))
                {
                    PgpObjectFactory factory = new PgpObjectFactory(input);

                    PgpPadding padding = (PgpPadding)factory.NextPgpObject();
                    IsTrue(Arrays.AreEqual(packet.GetPadding(), padding.GetPadding()));
                }
            }
        }

        [Test]
        public void KnownPaddingBytesTest()
        {
            byte[] known = Strings.ToByteArray("thisIsKnownPadding");
            PaddingPacket packet = new PaddingPacket(known);
            IsTrue(Arrays.AreEqual(known, packet.GetPadding()));
        }

        [Test]
        public void Random50BytesTest()
        {
            int len = 50;
            SecureRandom random = new SecureRandom();
            PaddingPacket packet = new PaddingPacket(len, random);
            IsEquals(len, packet.GetPadding().Length);
        }


        public override void PerformTest()
        {
            PaddingPacketReadFromStreamTest();
            PaddingPacketReadThreePacketsFromStreamTest();
            PaddingPacketEncodeTest();
            PaddingPacketEncodeThenDecodeTest();
            KnownPaddingBytesTest();
            Random50BytesTest();
        }
    }
}