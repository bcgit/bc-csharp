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
     * RipeMD160 IDigest Test
     */
    [TestFixture]
    public class RipeMD160DigestTest
		: ITest
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
            "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        };

        readonly static string MillionADigest = "52783243c1697bdbe16d37f97f68f08325dc1528";

        public string Name
        {
			get { return "RipeMD160"; }
        }

		public ITestResult Perform()
        {
            IDigest digest = new RipeMD160Digest();
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
            IDigest d = new RipeMD160Digest((RipeMD160Digest)digest);

            digest.BlockUpdate(mm, mm.Length/2, mm.Length - mm.Length/2);
            digest.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length-1])))
            {
                return new SimpleTestResult(false,
                    "RipeMD160 failing clone test"
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
                    "RipeMD160 failing clone test - part 2"
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
            ITest test = new RipeMD160DigestTest();
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
