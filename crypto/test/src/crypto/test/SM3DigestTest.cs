using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	/**
	 * standard vector test for SM3 digest from chinese specification
	 */
	[TestFixture]
	public class SM3DigestTest
	    : DigestTest
	{
	    private static string[] messages = {
	        // Standard test vectors
	        "abc",
	        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
	        // Non-standard test vectors
	        "",
	        "a",
	        "abcdefghijklmnopqrstuvwxyz",
	    };

	    private static string[] digests = {
	        // Standard test vectors
	        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
	        // Non-standard test vectors
	        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
	        "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88",
	        "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595",
	    };

	    private static string sixtyFourKdigest = "97049bdc8f0736bc7300eafa9980aeb9cf00f24f7ec3a8f1f8884954d7655c1d";
	    private static string million_a_digest = "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3";

	    public SM3DigestTest()
			: base(new SM3Digest(), messages, digests)
	    {
	    }

	    public override void PerformTest()
	    {
	        base.PerformTest();

	        sixtyFourKTest(sixtyFourKdigest);
	        millionATest(million_a_digest);
	    }

	    protected override IDigest CloneDigest(IDigest digest)
	    {
	        return new SM3Digest((SM3Digest)digest);
	    }

		public static void Main(
			string[] args)
		{
			RunTest(new SM3DigestTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
