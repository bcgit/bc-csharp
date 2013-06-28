using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;


namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * standard vector test for MD2
     * from RFC1319 by B.Kaliski of RSA Laboratories April 1992
     *
     */
    [TestFixture]
    public class MD2DigestTest
		: ITest
    {
        static private string testVec1 = "";
        static private string resVec1 = "8350e5a3e24c153df2275c9f80692773";
        static private string testVec2 = "61";
        static private string resVec2 = "32ec01ec4a6dac72c0ab96fb34c0b5d1";
        static private string testVec3 = "616263";
        static private string resVec3 = "da853b0d3f88d99b30283a69e6ded6bb";
        static private string testVec4 = "6d65737361676520646967657374";
        static private string resVec4 = "ab4f496bfb2a530b219ff33031fe06b0";
        static private string testVec5 = "6162636465666768696a6b6c6d6e6f707172737475767778797a";
        static private string resVec5 = "4e8ddff3650292ab5a4108c3aa47940b";
        static private string testVec6 = "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839";
        static private string resVec6 = "da33def2a42df13975352846c30338cd";
        static private string testVec7 = "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930";
        static private string resVec7 = "d5976f79d83d3a0dc9806c3c66f3efd8";

		public string Name
        {
			get { return "MD2"; }
        }

		public ITestResult Perform()
        {
            IDigest digest = new MD2Digest();
            byte[] resBuf = new byte[digest.GetDigestSize()];
            string resStr;

            //
            // test 1
            //
            byte[]  bytes = Hex.Decode(testVec1);
            digest.BlockUpdate(bytes, 0, bytes.Length);
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec1.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD2 failing standard vector test 1"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec1
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            //
            // test 2
            //
            bytes = Hex.Decode(testVec2);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec2.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD2 failing standard vector test 2"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec2
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            //
            // test 3
            //
            bytes = Hex.Decode(testVec3);
            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec3.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD2 failing standard vector test 3"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec3
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            //
            // test 4
            //

            bytes = Hex.Decode(testVec4);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD2 failing standard vector test 4"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec4
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }
            //
            // test 5
            //
            bytes = Hex.Decode(testVec5);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec5.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    //System.err.println(
                    "MD2 failing standard vector test 5"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec5
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }
            //
            // test 6
            //
            bytes = Hex.Decode(testVec6);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec6.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD2 failing standard vector test 6"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec6
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }
            //
            // test 7
            //
            bytes = Hex.Decode(testVec7);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec7.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD2 failing standard vector test 7"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec7
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

		public static void Main(
            string[] args)
        {
            ITest test = new MD2DigestTest();
            ITestResult result = test.Perform();

			Console.WriteLine(result);
        }

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
