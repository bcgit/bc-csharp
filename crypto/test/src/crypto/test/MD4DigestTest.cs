using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * standard vector test for MD4 from RFC 1320.
     */
    [TestFixture]
    public class MD4DigestTest
		: ITest
    {
//        static private string testVec1 = "";
        static private string resVec1 = "31d6cfe0d16ae931b73c59d7e0c089c0";

        static private string testVec2 = "61";
        static private string resVec2 = "bde52cb31de33e46245e05fbdbd6fb24";

        static private string testVec3 = "616263";
        static private string resVec3 = "a448017aaf21d8525fc10ae87aa6729d";

        static private string testVec4 = "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930";
        static private string resVec4 = "e33b4ddc9c38f2199c3e7b164fcc0536";

        public string Name
        {
			get { return "MD4"; }
        }

		public ITestResult Perform()
        {
            IDigest  digest = new MD4Digest();
            byte[]  resBuf = new byte[digest.GetDigestSize()];
            string  resStr;

            //
            // test 1
            //
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec1.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD4 failing standard vector test 1"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec1
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            //
            // test 2
            //
            byte[]  bytes = Hex.Decode(testVec2);

            digest.BlockUpdate(bytes, 0, bytes.Length);

            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec2.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD4 failing standard vector test 2"
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
                    "MD4 failing standard vector test 3"
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
                    "MD4 failing standard vector test 4"
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
            IDigest d = new MD4Digest((MD4Digest)digest);

            digest.BlockUpdate(bytes, bytes.Length/2, bytes.Length - bytes.Length/2);
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "MD4 failing standard vector test 5"
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
                    "MD4 failing standard vector test 5"
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
            ITest test = new MD4DigestTest();
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
