using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * standard vector test for SHA-256 from FIPS Draft 180-2.
     *
     * Note, the first two vectors are _not_ from the draft, the last three are.
     */
    [TestFixture]
    public class Sha256DigestTest
		: ITest
    {
//        static private string  testVec1 = "";
        static private string resVec1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        static private string testVec2 = "61";
        static private string resVec2 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";

        static private string testVec3 = "616263";
        static private string resVec3 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        static private string testVec4 = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
        static private string resVec4 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

        // 1 million 'a'
        static private string testVec5 = "61616161616161616161";
        static private string resVec5 = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

		public string Name
        {
			get { return "SHA256"; }
        }

		public ITestResult Perform()
        {
            IDigest digest = new Sha256Digest();
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
                    "SHA-256 failing standard vector test 1"
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
                    "SHA-256 failing standard vector test 2"
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
                    "SHA-256 failing standard vector test 3"
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
                    "SHA-256 failing standard vector test 4"
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
            IDigest d = new Sha256Digest((Sha256Digest)digest);

            digest.BlockUpdate(bytes, bytes.Length/2, bytes.Length - bytes.Length/2);
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "SHA-256 failing standard vector test 5"
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
                    "SHA-256 failing standard vector test 5"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec4
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            // test 6
            bytes = Hex.Decode(testVec5);
            for ( int i = 0; i < 100000; i++ )
            {
                digest.BlockUpdate(bytes, 0, bytes.Length);
            }
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec5.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "SHA-256 failing standard vector test 6"
                    + SimpleTest.NewLine
                    + "    expected: " + resVec5
                    + SimpleTest.NewLine
                    + "    got     : " + resStr);
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

		public static void Main(
			string[] args)
        {
            ITest test = new Sha256DigestTest();
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
