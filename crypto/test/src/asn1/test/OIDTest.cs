using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	/**
	 * X.690 test example
	 */
	[TestFixture]
	public class OidTest
		: SimpleTest
	{
		private static readonly byte[] req1 = Hex.Decode("0603813403");
        private static readonly byte[] req2 = Hex.Decode("06082A36FFFFFFDD6311");

		public override string Name
		{
			get { return "OID"; }
		}

		private void RecodeCheck(string oid, byte[] enc)
		{
			DerObjectIdentifier o = new DerObjectIdentifier(oid);
			DerObjectIdentifier encO = (DerObjectIdentifier) Asn1Object.FromByteArray(enc);

			if (!o.Equals(encO))
			{
				Fail("oid ID didn't match", o, encO);
			}

			byte[] bytes = o.GetDerEncoded();

			if (!Arrays.AreEqual(bytes, enc))
			{
				Fail("failed comparison test", Hex.ToHexString(enc), Hex.ToHexString(bytes));
			}
		}

		private void CheckValid(string oid)
		{
			DerObjectIdentifier o = new DerObjectIdentifier(oid);
			o = (DerObjectIdentifier)Asn1Object.FromByteArray(o.GetEncoded());

			if (!o.Id.Equals(oid))
			{
				Fail("failed oid check: " + oid);
			}
		}

		private void CheckInvalid(string oid)
		{
			try
			{
				new DerObjectIdentifier(oid);
				Fail("failed to catch bad oid: " + oid);
			}
			catch (FormatException)
			{
				// expected
			}
		}

		private void BranchCheck(string stem, string branch)
		{
			string expected = stem + "." + branch;
			string actual = new DerObjectIdentifier(stem).Branch(branch).Id;

			if (expected != actual)
			{
				Fail("failed 'branch' check for " + stem + "/" + branch);
			}
		}

		private void OnCheck(string stem, string test, bool expected)
		{
			if (expected != new DerObjectIdentifier(test).On(new DerObjectIdentifier(stem)))
			{
				Fail("failed 'on' check for " + stem + "/" + test);
			}
		}

		public override void PerformTest()
		{
			RecodeCheck("2.100.3", req1);
			RecodeCheck("1.2.54.34359733987.17", req2);

			CheckValid(PkcsObjectIdentifiers.Pkcs9AtContentType.Id);
			CheckValid("0.1");
			CheckValid("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
			CheckValid("1.2.123.12345678901.1.1.1");
			CheckValid("2.25.196556539987194312349856245628873852187.1");

			CheckInvalid("0");
			CheckInvalid("1");
			CheckInvalid("2");
			CheckInvalid("3.1");
			CheckInvalid("..1");
			CheckInvalid("192.168.1.1");
			CheckInvalid(".123452");
			CheckInvalid("1.");
			CheckInvalid("1.345.23.34..234");
			CheckInvalid("1.345.23.34.234.");
			CheckInvalid(".12.345.77.234");
			CheckInvalid(".12.345.77.234.");
			CheckInvalid("1.2.3.4.A.5");
			CheckInvalid("1,2");

			BranchCheck("1.1", "2.2");

			OnCheck("1.1", "1.1", false);
			OnCheck("1.1", "1.2", false);
			OnCheck("1.1", "1.2.1", false);
			OnCheck("1.1", "2.1", false);
			OnCheck("1.1", "1.11", false);
			OnCheck("1.12", "1.1.2", false);
			OnCheck("1.1", "1.1.1", true);
			OnCheck("1.1", "1.1.2", true);
		}

		public static void Main(string[] args)
		{
            RunTest(new OidTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
