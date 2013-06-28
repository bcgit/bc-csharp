using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	/// <remarks>Standard vector test for SHA-1 from "Handbook of Applied Cryptography", page 345.</remarks>
	[TestFixture]
	public class Sha1DigestTest
		: SimpleTest
	{
		//static private string testVec1 = "";
		static private string resVec1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

		static private string testVec2 = "61";
		static private string resVec2 = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8";

		static private string testVec3 = "616263";
		static private string resVec3 = "a9993e364706816aba3e25717850c26c9cd0d89d";

		static private string testVec4 = "6162636465666768696a6b6c6d6e6f707172737475767778797a";
		static private string resVec4 = "32d10c7b8cf96570ca04ce37f2a19d84240d3a89";

		public override string Name
		{
			get { return "SHA1"; }
		}

		public override void PerformTest()
		{
			IDigest digest = new Sha1Digest();
			byte[] resBuf = new byte[digest.GetDigestSize()];
			string resStr;

			//
			// test 1
			//
			digest.DoFinal(resBuf, 0);

			resStr = Hex.ToHexString(resBuf);
			if (!resVec1.Equals(resStr))
			{
				Fail("failing standard vector test 1" + SimpleTest.NewLine
					+ "    expected: " + resVec1 + SimpleTest.NewLine
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
				Fail("failing standard vector test 2" + SimpleTest.NewLine
					+ "    expected: " + resVec2 + SimpleTest.NewLine
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
				Fail("failing standard vector test 3" + SimpleTest.NewLine
					+ "    expected: " + resVec3 + SimpleTest.NewLine
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
				Fail("failing standard vector test 4" + SimpleTest.NewLine
					+ "    expected: " + resVec4 + SimpleTest.NewLine
					+ "    got     : " + resStr);
			}

			//
			// test 5
			//
			bytes = Hex.Decode(testVec4);

			digest.BlockUpdate(bytes, 0, bytes.Length / 2);

			// clone the IDigest
			IDigest d = new Sha1Digest((Sha1Digest)digest);

			digest.BlockUpdate(bytes, bytes.Length / 2, bytes.Length - bytes.Length / 2);
			digest.DoFinal(resBuf, 0);

			resStr = Hex.ToHexString(resBuf);
			if (!resVec4.Equals(resStr))
			{
				Fail("failing standard vector test 5" + SimpleTest.NewLine
					+ "    expected: " + resVec4 + SimpleTest.NewLine
					+ "    got     : " + resStr);
			}

			d.BlockUpdate(bytes, bytes.Length / 2, bytes.Length - bytes.Length / 2);
			d.DoFinal(resBuf, 0);

			resStr = Hex.ToHexString(resBuf);
			if (!resVec4.Equals(resStr))
			{
				Fail("failing standard vector test 5" + SimpleTest.NewLine
					+ "    expected: " + resVec4 + SimpleTest.NewLine
					+ "    got     : " + resStr);
			}
		}

		public static void Main(
			string[] args)
		{
			RunTest(new Sha1DigestTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
