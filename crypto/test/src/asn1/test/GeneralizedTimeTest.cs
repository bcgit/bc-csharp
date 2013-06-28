using System;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	/**
	 * X.690 test example
	 */
	public class GeneralizedTimeTest
		: SimpleTest
	{
		private static readonly string[] input =
		{
			"20020122122220",
			"20020122122220Z",
			"20020122122220-1000",
			"20020122122220+00",
			"20020122122220.1",
			"20020122122220.1Z",
			"20020122122220.1-1000",
			"20020122122220.1+00",
			"20020122122220.01",
			"20020122122220.01Z",
			"20020122122220.01-1000",
			"20020122122220.01+00",
			"20020122122220.001",
			"20020122122220.001Z",
			"20020122122220.001-1000",
			"20020122122220.001+00",
			"20020122122220.0001",
			"20020122122220.0001Z",
			"20020122122220.0001-1000",
			"20020122122220.0001+00",
			"20020122122220.0001+1000"
		};

		private static readonly string[] output =
		{
			"20020122122220",
			"20020122122220GMT+00:00",
			"20020122122220GMT-10:00",
			"20020122122220GMT+00:00",
			"20020122122220.1",
			"20020122122220.1GMT+00:00",
			"20020122122220.1GMT-10:00",
			"20020122122220.1GMT+00:00",
			"20020122122220.01",
			"20020122122220.01GMT+00:00",
			"20020122122220.01GMT-10:00",
			"20020122122220.01GMT+00:00",
			"20020122122220.001",
			"20020122122220.001GMT+00:00",
			"20020122122220.001GMT-10:00",
			"20020122122220.001GMT+00:00",
			"20020122122220.0001",
			"20020122122220.0001GMT+00:00",
			"20020122122220.0001GMT-10:00",
			"20020122122220.0001GMT+00:00",
			"20020122122220.0001GMT+10:00"
		};

		private static readonly string[] zOutput =
		{
			"20020122122220Z",
			"20020122122220Z",
			"20020122222220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122222220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122222220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122222220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122122220Z",
			"20020122222220Z",
			"20020122122220Z",
			"20020122022220Z"
		};
		
		private static readonly string[] mzOutput =
		{
			"20020122122220.000Z",
			"20020122122220.000Z",
			"20020122222220.000Z",
			"20020122122220.000Z",
			"20020122122220.100Z",
			"20020122122220.100Z",
			"20020122222220.100Z",
			"20020122122220.100Z",
			"20020122122220.010Z",
			"20020122122220.010Z",
			"20020122222220.010Z",
			"20020122122220.010Z",
			"20020122122220.001Z",
			"20020122122220.001Z",
			"20020122222220.001Z",
			"20020122122220.001Z",
			"20020122122220.000Z",
			"20020122122220.000Z",
			"20020122222220.000Z",
			"20020122122220.000Z",
			"20020122022220.000Z"
		};

		public override string Name
		{
			get { return "GeneralizedTime"; }
		}

		public override void PerformTest()
		{
			for (int i = 0; i != input.Length; i++)
			{
				DerGeneralizedTime t = new DerGeneralizedTime(input[i]);

				if (output[i].IndexOf('G') > 0)   // don't check local time the same way
				{
					if (!t.GetTime().Equals(output[i]))
					{
						Fail("failed conversion test");
					}

					if (!t.ToDateTime().ToString(@"yyyyMMddHHmmss\Z").Equals(zOutput[i]))
					{
						Fail("failed date conversion test");
					}
				}
				else
				{
					string offset = CalculateGmtOffset(t.ToDateTime());
					if (!t.GetTime().Equals(output[i] + offset))
					{
						Fail("failed conversion test");
					}
				}
			}

			for (int i = 0; i != input.Length; i++)
			{
				DerGeneralizedTime t = new DerGeneralizedTime(input[i]);

				if (!t.ToDateTime().ToString(@"yyyyMMddHHmmss.fff\Z").Equals(mzOutput[i]))
				{
					Console.WriteLine("{0} != {1}", t.ToDateTime().ToString(@"yyyyMMddHHmmss.SSS\Z"), mzOutput[i]);

					Fail("failed long date conversion test");
				}
			}
		}

		private string CalculateGmtOffset(
			DateTime date)
		{
			char sign = '+';

            // Note: GetUtcOffset incorporates Daylight Savings offset
			TimeSpan offset =  TimeZone.CurrentTimeZone.GetUtcOffset(date);
			if (offset.CompareTo(TimeSpan.Zero) < 0)
			{
				sign = '-';
				offset = offset.Duration();
			}
			int hours = offset.Hours;
			int minutes = offset.Minutes;

			return "GMT" + sign + Convert(hours) + ":" + Convert(minutes);
		}

		private string Convert(int time)
		{
			if (time < 10)
			{
				return "0" + time;
			}

			return time.ToString();
		}

		public static void Main(
			string[] args)
		{
			RunTest(new GeneralizedTimeTest());
		}
	}
}
