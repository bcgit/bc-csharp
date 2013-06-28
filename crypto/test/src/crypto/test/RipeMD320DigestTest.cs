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
    /// <summary> RipeMD320 IDigest Test</summary>
    [TestFixture]
    public class RipeMD320DigestTest
		: ITest
    {
        public string Name
        {
			get { return "RipeMD320"; }
        }

		internal static readonly string[] messages = new string[]{"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

		internal static readonly string[] digests = new string[]{"22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d", "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197", "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009", "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac", "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4", "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42"};

		internal const string MillionADigest = "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66";

		public virtual ITestResult Perform()
        {
            IDigest digest = new RipeMD320Digest();
            byte[] resBuf = new byte[digest.GetDigestSize()];

            for (int i = 0; i < messages.Length; i++)
            {
                byte[] m = Encoding.ASCII.GetBytes(messages[i]);
                digest.BlockUpdate(m, 0, m.Length);
                digest.DoFinal(resBuf, 0);

                if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[i])))
                {
                    Console.WriteLine(Name + ": Vector " + i + " failed" + "    expected: " + digests[i] + SimpleTest.NewLine + "    got     : " + Hex.ToHexString(resBuf));
                    return new SimpleTestResult(false, Name + ": Vector " + i + " failed");
                }
            }

            //
            // test 2
            //
            byte[] m2 = Encoding.ASCII.GetBytes(messages[messages.Length - 1]);

            digest.BlockUpdate(m2, 0, m2.Length / 2);

            // clone the IDigest
            IDigest d = new RipeMD320Digest((RipeMD320Digest) digest);

            digest.BlockUpdate(m2, m2.Length / 2, m2.Length - m2.Length / 2);
            digest.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length - 1])))
            {
                return new SimpleTestResult(false, "RipeMD320 failing clone test" + SimpleTest.NewLine + "    expected: " + digests[digests.Length - 1] + SimpleTest.NewLine + "    got     : " + Hex.ToHexString(resBuf));
            }

            d.BlockUpdate(m2, m2.Length / 2, m2.Length - m2.Length / 2);
            d.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[digests.Length - 1])))
            {
                return new SimpleTestResult(false, "RipeMD320 failing clone test - part 2" + SimpleTest.NewLine + "    expected: " + digests[digests.Length - 1] + SimpleTest.NewLine + "    got     : " + Hex.ToHexString(resBuf));
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
            ITest test = new RipeMD320DigestTest();
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
