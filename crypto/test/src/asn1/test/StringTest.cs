using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    /**
	* X.690 test example
	*/
    [TestFixture]
    public class StringTest
        : SimpleTest
    {
        public override string Name
        {
            get { return "String"; }
        }

        public override void PerformTest()
        {
            DerBitString bs = new DerBitString(
                new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef });

            if (!bs.GetString().Equals("#0309000123456789ABCDEF"))
            {
                Fail("DerBitString.GetString() result incorrect");
            }

            if (!bs.ToString().Equals("#0309000123456789ABCDEF"))
            {
                Fail("DerBitString.ToString() result incorrect");
            }

            bs = new DerBitString(
                new byte[] { (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 });

            if (!bs.GetString().Equals("#030900FEDCBA9876543210"))
            {
                Fail("DerBitString.GetString() result incorrect");
            }

            if (!bs.ToString().Equals("#030900FEDCBA9876543210"))
            {
                Fail("DerBitString.ToString() result incorrect");
            }

            DerUniversalString us = new DerUniversalString(
                new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef });

            if (!us.GetString().Equals("#1C080123456789ABCDEF"))
            {
                Fail("DerUniversalString.GetString() result incorrect");
            }

            if (!us.ToString().Equals("#1C080123456789ABCDEF"))
            {
                Fail("DerUniversalString.ToString() result incorrect");
            }

            us = new DerUniversalString(
                new byte[] { (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 });

            if (!us.GetString().Equals("#1C08FEDCBA9876543210"))
            {
                Fail("DerUniversalString.GetString() result incorrect");
            }

            if (!us.ToString().Equals("#1C08FEDCBA9876543210"))
            {
                Fail("DerUniversalString.ToString() result incorrect");
            }

            byte[] t61Bytes = new byte[] { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8 };
            string t61String = Encoding.GetEncoding("iso-8859-1").GetString(t61Bytes, 0, t61Bytes.Length);
            DerT61String t61 = new DerT61String(t61Bytes);

            if (!t61.GetString().Equals(t61String))
            {
                Fail("DerT61String.GetString() result incorrect");
            }

            if (!t61.ToString().Equals(t61String))
            {
                Fail("DerT61String.ToString() result incorrect");
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        /// <summary>
        /// A BMPString whose declared length is far larger than the data behind it must fail on the truncated content,
        /// not on the way to allocating for the declared length.
        /// </summary>
        /// <remarks>
        /// Reading through DefiniteLengthInputStream.ToArray grows the buffer as bytes arrive, so this should return
        /// promptly with a truncation error.
        /// </remarks>
        [Test]
        public void CheckBmpStringHostileLength()
        {
            //long maxMemory = Runtime.getRuntime().maxMemory();
            //int limit = maxMemory > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int)maxMemory;
            int limit = Arrays.MaxLength;
            int declared = (limit - 1024) & ~1;

            byte[] header = new byte[]{ 0x1E, 0x84,
                (byte)(declared >> 24), (byte)(declared >> 16), (byte)(declared >> 8), (byte)declared,
                0x00, 0x41
            };

            try
            {
                // wrapped so the stream's size cannot be discovered - i.e. read off a socket, where
                // the declared length is all the parser has to go on
                using (var asn1 = new Asn1InputStream(new NoSeekMemoryStream(header)))
                {
                    asn1.ReadObject();
                }

                Assert.Fail("hostile BMPString length not rejected");
            }
            catch (IOException)
            {
                // expected: the content runs out long before the declared length
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
