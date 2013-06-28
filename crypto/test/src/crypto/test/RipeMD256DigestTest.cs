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
    /// <summary> RipeMD256 IDigest Test</summary>
    [TestFixture]
    public class RipeMD256DigestTest
		: ITest
    {
        public string Name
        {
			get { return "RipeMD256"; }
        }

		internal static readonly string[] messages = new string[]{"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

		internal static readonly string[] digests = new string[]{"02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e", "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133", "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f", "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8", "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd"};

		internal const string MillionADigest = "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978";

		public virtual ITestResult Perform()
        {
            IDigest digest = new RipeMD256Digest();
            byte[] resBuf = new byte[digest.GetDigestSize()];

			for (int i = 0; i < messages.Length; i++)
            {
                byte[] m = Encoding.ASCII.GetBytes(messages[i]);
                digest.BlockUpdate(m, 0, m.Length);
                digest.DoFinal(resBuf, 0);

                if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[i])))
                {
                    return new SimpleTestResult(false, Name + ": Vector " + i + " failed" + "    expected: " + digests[i] + SimpleTest.NewLine + "    got     : " + Hex.ToHexString(resBuf));
                }
            }

            //
            // test 2
            //
            byte[] m2 = Encoding.ASCII.GetBytes(messages[messages.Length - 1]);
            digest.BlockUpdate(m2, 0, m2.Length / 2);

			// clone the IDigest
            IDigest d = new RipeMD256Digest((RipeMD256Digest) digest);

            digest.BlockUpdate(m2, m2.Length / 2, m2.Length - m2.Length / 2);
            digest.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length - 1])))
            {
                return new SimpleTestResult(false, "RipeMD256 failing clone test" + SimpleTest.NewLine + "    expected: " + digests[digests.Length - 1] + SimpleTest.NewLine + "    got     : " + Hex.ToHexString(resBuf));
            }

            d.BlockUpdate(m2, m2.Length / 2, m2.Length - m2.Length / 2);
            d.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length - 1])))
            {
                return new SimpleTestResult(false, "RipeMD256 failing clone test - part 2" + SimpleTest.NewLine + "    expected: " + digests[digests.Length - 1] + SimpleTest.NewLine + "    got     : " + Hex.ToHexString(resBuf));
            }

            for (int i = 0; i < 1000000; i++)
            {
                digest.Update((byte) 'a');
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
            ITest test = new RipeMD256DigestTest();
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
