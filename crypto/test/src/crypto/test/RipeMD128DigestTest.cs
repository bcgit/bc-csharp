using System;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * RipeMD128 IDigest Test
     */
    [TestFixture]
    public class RipeMD128DigestTest: ITest
    {
        readonly static string[] messages =
        {
            "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        };

        readonly static string[] digests = {
            "cdf26213a150dc3ecb610f18f6b38b46",
            "86be7afa339d0fc7cfc785e72f578d33",
            "c14a12199c66e4ba84636b0f69144c77",
            "9e327b3d6e523062afc1132d7df9d1b8",
            "fd2aa607f71dc8f510714922b371834e",
            "a1aa0689d0fafa2ddc22e88b49133a06",
            "d1e959eb179c911faea4624c60c5c702",
            "3f45ef194732c2dbb2c4a2c769795fa3"
        };

		readonly static string MillionADigest = "4a7f5723f954eba1216c9d8f6320431f";

        public string Name
        {
			get { return "RipeMD128"; }
        }

		public ITestResult Perform()
        {
            IDigest digest = new RipeMD128Digest();
            byte[] resBuf = new byte[digest.GetDigestSize()];

            for (int i = 0; i < messages.Length; i++)
            {
                byte[] m = Encoding.ASCII.GetBytes(messages[i]);
                digest.BlockUpdate(m, 0, m.Length);
                digest.DoFinal(resBuf, 0);

                if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[i])))
                {
                    return new SimpleTestResult(false, Name + ": Vector " + i + " failed");
                }
            }

            //
            // test 2
            //
            byte[] mm = Encoding.ASCII.GetBytes(messages[messages.Length-1]);

            digest.BlockUpdate(mm, 0, mm.Length/2);

            // clone the IDigest
            IDigest d = new RipeMD128Digest((RipeMD128Digest)digest);

            digest.BlockUpdate(mm, mm.Length/2, mm.Length - mm.Length/2);
            digest.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length-1])))
            {
                return new SimpleTestResult(false,
                    "RipeMD128 failing clone test"
                    + SimpleTest.NewLine
                    + "    expected: " + digests[digests.Length-1]
                    + SimpleTest.NewLine
                    + "    got     : " + Hex.ToHexString(resBuf));
            }

            d.BlockUpdate(mm, mm.Length/2, mm.Length - mm.Length/2);
            d.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length-1])))
            {
                return new SimpleTestResult(false,
                    "RipeMD128 failing clone test - part 2"
                    + SimpleTest.NewLine
                    + "    expected: " +  digests[digests.Length-1]
                    + SimpleTest.NewLine
                    + "    got     : " + Hex.ToHexString(resBuf));
            }

            for (int i = 0; i < 1000000; i++)
            {
                digest.Update((byte)'a');
            }
            digest.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(MillionADigest)))
            {
                return new SimpleTestResult(false, Name + ": Million a's failed");
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

        public static void Main(
			string[] args)
        {
            ITest test = new RipeMD128DigestTest();
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
