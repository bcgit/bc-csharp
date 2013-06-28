using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;


namespace Org.BouncyCastle.Crypto.Tests
{
	/// <remarks>Standard vector test for MD5 from "Handbook of Applied Cryptography", page 345.</remarks>
    [TestFixture]
    public class MD5DigestTest
		: ITest
    {
//        static private string testVec1 = "";
        static private string resVec1 = "d41d8cd98f00b204e9800998ecf8427e";

        static private string testVec2 = "61";
        static private string resVec2 = "0cc175b9c0f1b6a831c399e269772661";

        static private string testVec3 = "616263";
        static private string resVec3 = "900150983cd24fb0d6963f7d28e17f72";

        static private string testVec4 = "6162636465666768696a6b6c6d6e6f707172737475767778797a";
        static private string resVec4 = "c3fcd3d76192e4007dfb496cca67e13b";

        public string Name
        {
			get { return "MD5"; }
        }

		public ITestResult Perform()
        {
            IDigest digest = new MD5Digest();
            byte[] resBuf = new byte[digest.GetDigestSize()];
            string resStr;

            //
            // test 1
            //
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec1.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD5 failing standard vector test 1"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec1
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            //
            // test 2
            //
            byte[] bytes = Hex.Decode(testVec2);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec2.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD5 failing standard vector test 2"
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
                    "MD5 failing standard vector test 3"
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
                    "MD5 failing standard vector test 4"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec4
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            //
            // test 5
            //
            bytes = Hex.Decode(testVec4);

            digest.BlockUpdate(bytes, 0, bytes.Length/2);

            // clone the IDigest
            IDigest d = new MD5Digest((MD5Digest)digest);

            digest.BlockUpdate(bytes, bytes.Length/2, bytes.Length - bytes.Length/2);
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD5 failing standard vector test 5"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec4
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            d.BlockUpdate(bytes, bytes.Length/2, bytes.Length - bytes.Length/2);
            d.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD5 failing standard vector test 5"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec4
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }
            return new SimpleTestResult(true, Name + ": Okay");
        }

        public static void Main(
            string[] args)
        {
            ITest test = new MD5DigestTest();
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
