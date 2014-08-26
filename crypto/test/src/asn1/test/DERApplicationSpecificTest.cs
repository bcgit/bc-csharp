using System;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	[TestFixture]
	public class DerApplicationSpecificTest
		: SimpleTest
	{
		private static readonly byte[] impData = Hex.Decode("430109");

		private static readonly byte[] certData = Hex.Decode(
			  "7F218201897F4E8201495F290100420E44454356434145504153533030317F49"
			+ "81FD060A04007F00070202020202811CD7C134AA264366862A18302575D1D787"
			+ "B09F075797DA89F57EC8C0FF821C68A5E62CA9CE6C1C299803A6C1530B514E18"
			+ "2AD8B0042A59CAD29F43831C2580F63CCFE44138870713B1A92369E33E2135D2"
			+ "66DBB372386C400B8439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C"
			+ "1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D376"
			+ "1402CD851CD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A793"
			+ "9F863904393EE8E06DB6C7F528F8B4260B49AA93309824D92CDB1807E5437EE2"
			+ "E26E29B73A7111530FA86B350037CB9415E153704394463797139E148701015F"
			+ "200E44454356434145504153533030317F4C0E060904007F0007030102015301"
			+ "C15F25060007000400015F24060009000400015F37384CCF25C59F3612EEE188"
			+ "75F6C5F2E2D21F0395683B532A26E4C189B71EFE659C3F26E0EB9AEAE9986310"
			+ "7F9B0DADA16414FFA204516AEE2B");

		public override string Name
		{
			get { return "DerApplicationSpecific"; }
		}

		public override void PerformTest()
		{
			DerInteger val = new DerInteger(9);

			DerApplicationSpecific tagged = new DerApplicationSpecific(false, 3, val);

			if (!AreEqual(impData, tagged.GetEncoded()))
			{
				Fail("implicit encoding failed");
			}

			DerInteger recVal = (DerInteger) tagged.GetObject(Asn1Tags.Integer);

			if (!val.Equals(recVal))
			{
				Fail("implicit read back failed");
			}

			DerApplicationSpecific certObj = (DerApplicationSpecific)
				Asn1Object.FromByteArray(certData);

			if (!certObj.IsConstructed() || certObj.ApplicationTag != 33)
			{
				Fail("parsing of certificate data failed");
			}

			byte[] encoded = certObj.GetDerEncoded();

			if (!Arrays.AreEqual(certData, encoded))
			{
				Console.WriteLine(Encoding.ASCII.GetString(certData, 0, certData.Length).Substring(0, 20));
				Console.WriteLine(Encoding.ASCII.GetString(encoded, 0, encoded.Length).Substring(0, 20));
				Fail("re-encoding of certificate data failed");
			}
		}

		public static void Main(
			string[] args)
		{
			RunTest(new DerApplicationSpecificTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
