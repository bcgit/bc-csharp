using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class BitStringTest
        : SimpleTest
    {
        private void DoTestZeroLengthStrings()
        {
            // basic construction
            DerBitString s1 = new DerBitString(new byte[0], 0);

            // check GetBytes()
            s1.GetBytes();

            // check encoding/decoding
            DerBitString derBit = (DerBitString)Asn1Object.FromByteArray(s1.GetEncoded());

            if (!Arrays.AreEqual(s1.GetEncoded(), Hex.Decode("030100")))
            {
                Fail("zero encoding wrong");
            }

            try
            {
                new DerBitString(null, 1);
                Fail("exception not thrown");
            }
            catch (ArgumentNullException)
            {
            }

            try
            {
                new DerBitString(new byte[0], 1);
                Fail("exception not thrown");
            }
            catch (ArgumentException)
            {
            }

            try
            {
                new DerBitString(new byte[1], 8);
                Fail("exception not thrown");
            }
            catch (ArgumentException)
            {
            }

            DerBitString s2 = new DerBitString(0);
            if (!Arrays.AreEqual(s1.GetEncoded(), s2.GetEncoded()))
            {
                Fail("zero encoding wrong");
            }
        }

        private void DoTestRandomPadBits()
        {
            byte[] test = Hex.Decode("030206c0");

            byte[] test1 = Hex.Decode("030206f0");
            byte[] test2 = Hex.Decode("030206c1");
            byte[] test3 = Hex.Decode("030206c7");
            byte[] test4 = Hex.Decode("030206d1");

            EncodingCheck(test, test1);
            EncodingCheck(test, test2);
            EncodingCheck(test, test3);
            EncodingCheck(test, test4);
        }
        
        private void DoTestRandomPadArraySegmentBits()
        {
            byte[] test = Hex.Decode("030206c0");

            byte[] test1 = Hex.Decode("030206f0");
            byte[] test2 = Hex.Decode("030206c1");
            byte[] test3 = Hex.Decode("030206c7");
            byte[] test4 = Hex.Decode("030206d1");

            EncodingCheck(MakeRandomArraySegment(test), MakeRandomArraySegment(test1));
            EncodingCheck(MakeRandomArraySegment(test), MakeRandomArraySegment(test2));
            EncodingCheck(MakeRandomArraySegment(test), MakeRandomArraySegment(test3));
            EncodingCheck(MakeRandomArraySegment(test), MakeRandomArraySegment(test4));
        }

        private static ArraySegment<byte> MakeRandomArraySegment(byte[] buffer)
        {
            var random = new Random();

            var array = new byte[buffer.Length + random.Next(100)];

            var offset = random.Next(array.Length - buffer.Length);

            random.NextBytes(array);

            buffer.CopyTo(array, offset);

            return new ArraySegment<byte>(array, offset, buffer.Length);
        }
        
        private void EncodingCheck(byte[] derData, byte[] dlData)
        {
            if (Arrays.AreEqual(derData, Asn1Object.FromByteArray(dlData).GetEncoded()))
            {
                Fail("failed DL check");
            }
            DerBitString dl = DerBitString.GetInstance(dlData);

            IsTrue("DL test failed", dl is DLBitString);
            if (!Arrays.AreEqual(derData, Asn1Object.FromByteArray(dlData).GetDerEncoded()))
            {
                Fail("failed DER check");
            }
            try
            {
                // GetInstance should work for "an object that can be converted into [a DerBitString]".
                DerBitString.GetInstance(dlData);
            }
            catch (ArgumentException)
            {
                Fail("failed DL encoding conversion");
            }
            DerBitString der = DerBitString.GetInstance(derData);
            IsTrue("DER test failed", typeof(DerBitString) == der.GetType());
        }
        
        private void EncodingCheck(ArraySegment<byte> derData, ArraySegment<byte> dlData)
        {
            var encodeed = Asn1Object.FromByteArray(dlData).GetEncoded();

            if (Arrays.AreEqual(derData.Array, derData.Offset, derData.Offset + derData.Count, encodeed, 0, encodeed.Length))
            {
                Fail("failed DL check");
            }
            DerBitString dl = DerBitString.GetInstance(dlData);

            IsTrue("DL test failed", dl is DLBitString);

            encodeed = Asn1Object.FromByteArray(dlData).GetDerEncoded();
            if (!Arrays.AreEqual(derData.Array, derData.Offset, derData.Offset + derData.Count, encodeed, 0, encodeed.Length))
            {
                Fail("failed DER check");
            }
            try
            {
                // GetInstance should work for "an object that can be converted into [a DerBitString]".
                DerBitString.GetInstance(dlData);
            }
            catch (ArgumentException)
            {
                Fail("failed DL encoding conversion");
            }
            DerBitString der = DerBitString.GetInstance(derData);
            IsTrue("DER test failed", typeof(DerBitString) == der.GetType());
        }

        public override void PerformTest()
        {
            KeyUsage k = new KeyUsage(KeyUsage.DigitalSignature);
            if ((k.GetBytes()[0] != (byte)KeyUsage.DigitalSignature) || (k.PadBits != 7))
            {
                Fail("failed digitalSignature");
            }

            k = new KeyUsage(KeyUsage.NonRepudiation);
            if ((k.GetBytes()[0] != (byte)KeyUsage.NonRepudiation) || (k.PadBits != 6))
            {
                Fail("failed nonRepudiation");
            }

            k = new KeyUsage(KeyUsage.KeyEncipherment);
            if ((k.GetBytes()[0] != (byte)KeyUsage.KeyEncipherment) || (k.PadBits != 5))
            {
                Fail("failed keyEncipherment");
            }

            k = new KeyUsage(KeyUsage.CrlSign);
            if ((k.GetBytes()[0] != (byte)KeyUsage.CrlSign)  || (k.PadBits != 1))
            {
                Fail("failed cRLSign");
            }

            k = new KeyUsage(KeyUsage.DecipherOnly);
            if ((k.GetBytes()[1] != (byte)(KeyUsage.DecipherOnly >> 8))  || (k.PadBits != 7))
            {
                Fail("failed decipherOnly");
            }

			// test for zero length bit string
			try
			{
				Asn1Object.FromByteArray(new DerBitString(new byte[0], 0).GetEncoded());
			}
			catch (IOException e)
			{
				Fail(e.ToString());
			}

            DoTestRandomPadBits();
            DoTestRandomPadArraySegmentBits();
            DoTestZeroLengthStrings();
        }

        public override string Name
        {
			get { return "BitString"; }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
