using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// Standard vector test for SHA-512 from FIPS Draft 180-2.
    /// Note, the first two vectors are _not_ from the draft, the last three are.
    /// </summary>
    [TestFixture]
    public class Sha512DigestTest
		: ITest
    {
        public string Name
        {
			get { return "SHA512"; }
        }

		//private static string testVec1 = "";
        private static string resVec1 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

        private static string testVec2 = "61";
        private static string resVec2 = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75";

        private static string testVec3 = "616263";
        private static string resVec3 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

        private static string testVec4 = "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475";
        private static string resVec4 = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

        // 1 million 'a'
        private static string testVec5 = "61616161616161616161";
        private static string resVec5 = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

        public virtual ITestResult Perform()
        {
            IDigest digest = new Sha512Digest();
            byte[] resBuf = new byte[digest.GetDigestSize()];
            string resStr;

            //
            // test 1
            //
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec1.Equals(resStr))
            {
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 1" + SimpleTest.NewLine + "    expected: " + resVec1 + SimpleTest.NewLine + "    got     : " + resStr);
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
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 2" + SimpleTest.NewLine + "    expected: " + resVec2 + SimpleTest.NewLine + "    got     : " + resStr);
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
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 3" + SimpleTest.NewLine + "    expected: " + resVec3 + SimpleTest.NewLine + "    got     : " + resStr);
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
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 4" + SimpleTest.NewLine + "    expected: " + resVec4 + SimpleTest.NewLine + "    got     : " + resStr);
            }

            //
            // test 5
            //
            bytes = Hex.Decode(testVec4);

            digest.BlockUpdate(bytes, 0, bytes.Length / 2);

            // clone the IDigest
            IDigest d = new Sha512Digest((Sha512Digest)digest);

            digest.BlockUpdate(bytes, bytes.Length / 2, bytes.Length - bytes.Length / 2);
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 5" + SimpleTest.NewLine + "    expected: " + resVec4 + SimpleTest.NewLine + "    got     : " + resStr);
            }

            d.BlockUpdate(bytes, bytes.Length / 2, bytes.Length - bytes.Length / 2);
            d.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec4.Equals(resStr))
            {
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 5" + SimpleTest.NewLine + "    expected: " + resVec4 + SimpleTest.NewLine + "    got     : " + resStr);
            }

            // test 6
            bytes = Hex.Decode(testVec5);
            for (int i = 0; i < 100000; i++)
            {
                digest.BlockUpdate(bytes, 0, bytes.Length);
            }
            digest.DoFinal(resBuf, 0);

            resStr = Hex.ToHexString(resBuf);
            if (!resVec5.Equals(resStr))
            {
                return new SimpleTestResult(false, "SHA-512 failing standard vector test 6" + SimpleTest.NewLine + "    expected: " + resVec5 + SimpleTest.NewLine + "    got     : " + resStr);
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

        public static void Main(
            string[] args)
        {
            ITest test = new Sha512DigestTest();
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
