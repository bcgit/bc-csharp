using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * standard vector test for SHA-224 from RFC 3874 - only the last three are in
     * the RFC.
     */
    [TestFixture]
    public class Sha224DigestTest
        : ITest
    {
        private const string testVec1 = "";
        private const string resVec1 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";

		private const string testVec2 = "61";
        private const string resVec2 = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5";

		private const string testVec3 = "616263";
        private const string resVec3 = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

		private const string testVec4 = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
        private const string resVec4 = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";

		// 1 million 'a'
        private const string testVec5 = "61616161616161616161";
        private const string resVec5 = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";

		public string Name
        {
			get { return "SHA224"; }
        }

		public ITestResult Perform()
        {
            IDigest digest = new Sha224Digest();
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
                    "SHA-224 failing standard vector test 1"
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
                    "SHA-224 failing standard vector test 2"
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
                    "SHA-224 failing standard vector test 3"
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
                    "SHA-224 failing standard vector test 4"
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
            IDigest d = new Sha224Digest((Sha224Digest)digest);

            digest.BlockUpdate(bytes, bytes.Length/2, bytes.Length - bytes.Length/2);
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false,
                    "SHA-224 failing standard vector test 5"
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
                    "SHA-224 failing standard vector test 5"
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
                    "SHA-224 failing standard vector test 6"
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
            ITest test = new Sha224DigestTest();
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
