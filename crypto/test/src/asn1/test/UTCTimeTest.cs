using System.Globalization;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	/**
	* X.690 test example
	*/
	[TestFixture]
	public class UtcTimeTest
		: SimpleTest
	{
		private static readonly string[] input =
		{
			"020122122220Z",
			"020122122220-1000",
			"020122122220+1000",
			"0201221222Z",
			"0201221222-1000",
			"0201221222+1000",
			"550122122220Z",
			"5501221222Z",
            "4007270730Z",
        };

		private static readonly string[] outputPre2040 =
		{
			"20020122122220Z",
			"20020122222220Z",
			"20020122022220Z",
			"20020122122200Z",
			"20020122222200Z",
			"20020122022200Z",
			"19550122122220Z",
			"19550122122200Z",
            "19400727073000Z",
        };

		private static readonly string[] outputPost2040 =
		{
			"20020122122220Z",
			"20020122222220Z",
			"20020122022220Z",
			"20020122122200Z",
			"20020122222200Z",
			"20020122022200Z",
			"19550122122220Z",
			"19550122122200Z",
            "20400727073000Z",
        };

		public override string Name
		{
			get { return "UTCTime"; }
		}

		public override void PerformTest()
		{
			bool pre2040 = DateTimeFormatInfo.InvariantInfo.Calendar.TwoDigitYearMax < 2040;
			string[] outputDefault = pre2040 ? outputPre2040 : outputPost2040;

            for (int i = 0; i != input.Length; i++)
			{
				DerUtcTime t = new DerUtcTime(input[i]);

                if (!t.ToDateTime().ToString(@"yyyyMMddHHmmssK").Equals(outputDefault[i]))
				{
					Fail("failed date shortened conversion test " + i);
				}

                if (!t.ToDateTime(2029).ToString(@"yyyyMMddHHmmssK").Equals(outputPre2040[i]))
                {
                    Fail("failed date conversion test " + i);
                }

                if (!t.ToDateTime(2049).ToString(@"yyyyMMddHHmmssK").Equals(outputPost2040[i]))
                {
                    Fail("failed date conversion test " + i);
                }
            }
        }

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
