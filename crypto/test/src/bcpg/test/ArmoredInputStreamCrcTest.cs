using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.Tests
{
    /// <summary>
    /// Check correct handling of the CRC, in particular that multiple occurrences are detected and raise
    /// an error instead of leading possibly to a StackOverflowException.
    /// </summary>
    [TestFixture]
    public class ArmoredInputStreamCrcTest
    {
        /// <summary>
        /// 60,000 checksum lines is ~360KB of plain ASCII, which used to be enough to exhaust a default
        /// thread stack. The failure to look for is a StackOverflowException, not the message.
        /// </summary>
        [Test]
        public void RepeatedChecksumLineIsRejected()
        {
            byte[] armor = RepeatedChecksumArmor(60000);

            try
            {
                Drain(armor);
                Assert.Fail("repeated checksum lines accepted");
            }
            catch (StackOverflowException)
            {
                Assert.Fail("ReadByte() recursed to StackOverflowException");
            }
            catch (IOException e)
            {
                Assert.That(e.Message.Contains("crc"));
            }
        }

        /// <summary>
        /// The same trailer appended to a real armored body, which is how it would actually arrive.
        /// </summary>
        [Test]
        public void RepeatedChecksumAfterRealBodyIsRejected()
        {
            var data = Strings.ToByteArray("the quick brown fox");

            MemoryStream bOut = new MemoryStream();
            using (var aOut = new ArmoredOutputStream(bOut))
            {
                aOut.Write(data, 0, data.Length);
            }

            string armored = Strings.FromByteArray(bOut.ToArray());

            // keep everything up to and including the real checksum line, then repeat one
            int tail = armored.IndexOf("-----END");
            StringBuilder sb = new StringBuilder(armored.Substring(0, tail));
            for (int i = 0; i != 20000; i++)
            {
                sb.Append("=twTO\n");
            }
            sb.Append(armored.Substring(tail));

            try
            {
                Drain(Strings.ToByteArray(sb.ToString()));
                Assert.Fail("repeated checksum lines after a body accepted");
            }
            catch (StackOverflowException)
            {
                Assert.Fail("ReadByte() recursed to StackOverflowException");
            }
            catch (IOException e)
            {
                Assert.That(e.Message.Contains("crc"));
            }
        }

        /// <summary>
        /// The compatibility assertion: one checksum line, as every real message carries.
        /// </summary>
        [Test]
        public void WellFormedArmorStillRoundTrips()
        {
            byte[] data = Strings.ToByteArray("the quick brown fox jumps over the lazy dog");

            MemoryStream bOut = new MemoryStream();
            using (var aOut = new ArmoredOutputStream(bOut))
            {
                aOut.Write(data, 0, data.Length);
            }

            byte[] armored = bOut.ToArray();
            byte[] recovered;
            using (var aIn = new ArmoredInputStream(new MemoryStream(armored, false)))
            {
                recovered = Streams.ReadAll(aIn);
            }

            Assert.That(Arrays.AreEqual(data, recovered), "armored round trip");

            // Two messages back to back, which is what proves the rejection is per-message: the armor
            // tail clears crcFound, so the second message's checksum must not read as a repeat of the
            // first. Note ArmoredInputStream runs the two bodies together into one stream of content
            // rather than stopping at the first tail - that is long-standing behaviour, unchanged here,
            // and what matters is that both bodies come through instead of the second being refused.
            MemoryStream twoOut = new MemoryStream();
            using (twoOut)
            {
                twoOut.Write(armored, 0, armored.Length);
                twoOut.Write(armored, 0, armored.Length);
            }

            byte[] both;
            using (var twoIn = new ArmoredInputStream(new MemoryStream(twoOut.ToArray(), false)))
            {
                both = Streams.ReadAll(twoIn);
            }

            Assert.That(Arrays.AreEqual(Arrays.Concatenate(data, data), both), "two messages");
        }

        private static void Drain(byte[] armor)
        {
            using (var aIn = new ArmoredInputStream(new MemoryStream(armor, false)))
            {
                Streams.Drain(aIn);
            }
        }

        private static byte[] RepeatedChecksumArmor(int lines)
        {
            StringBuilder sb = new StringBuilder();

            // no headers and no data at all: the CRC-24 of nothing is its initial value, so every line
            // matches. A CRLF-terminated header block instead trips the armor header parse first, which
            // is an earlier rejection and would not reach the checksum branch being tested here.
            sb.Append("-----BEGIN PGP MESSAGE-----\n\n\n");
            for (int i = 0; i != lines; i++)
            {
                sb.Append("=twTO\n");
            }
            sb.Append("-----END PGP MESSAGE-----\n");

            return Strings.ToByteArray(sb.ToString());
        }
    }
}
