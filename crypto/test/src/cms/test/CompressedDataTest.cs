using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
    [Parallelizable(ParallelScope.All)]
    public class CompressedDataTest
	{
		private static readonly byte[] TEST_DATA = Encoding.ASCII.GetBytes("Hello world!");

		private static readonly byte[] compData = Base64.Decode(
			  "MIAGCyqGSIb3DQEJEAEJoIAwgAIBADANBgsqhkiG9w0BCRADCDCABgkqhkiG9w0BBwGggCSABIIC"
			+ "Hnic7ZRdb9owFIbvK/k/5PqVYPFXGK12YYyboVFASSp1vQtZGiLRACZE49/XHoUW7S/0tXP8Efux"
			+ "fU5ivWnasml72XFb3gb5druui7ytN803M570nii7C5r8tfwR281hy/p/KSM3+jzH5s3+pbQ90xSb"
			+ "P3VT3QbLusnt8WPIuN5vN/vaA2+DulnXTXkXvNTr8j8ouZmkCmGI/UW+ZS/C8zP0bz2dz0zwLt+1"
			+ "UEk2M8mlaxjRMByAhZTj0RGYg4TvogiRASROsZgjpVcJCb1KV6QzQeDJ1XkoQ5Jm+C5PbOHZZGRi"
			+ "v+ORAcshOGeCcdFJyfgFxdtCdEcmOrbinc/+BBMzRThEYpwl+jEBpciSGWQkI0TSlREmD/eOHb2D"
			+ "SGLuESm/iKUFt1y4XHBO2a5oq0IKJKWLS9kUZTA7vC5LSxYmgVL46SIWxIfWBQd6AdrnjLmH94UT"
			+ "vGxVibLqRCtIpp4g2qpdtqK1LiOeolpVK5wVQ5P7+QjZAlrh0cePYTx/gNZuB9Vhndtgujl9T/tg"
			+ "W9ogK+3rnmg3YWygnTuF5GDS+Q/jIVLnCcYZFc6Kk/+c80wKwZjwdZIqDYWRH68MuBQSXLgXYXj2"
			+ "3CAaYOBNJMliTl0X7eV5DnoKIFSKYdj3cRpD/cK/JWTHJRe76MUXnfBW8m7Hd5zhQ4ri2NrVF/WL"
			+ "+kV1/3AGSlJ32bFPd2BsQD8uSzIx6lObkjdz95c0AAAAAAAAAAAAAAAA");

		private static readonly byte[] uncompData = Base64.Decode(
			  "Q29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9FREktWDEyOyBuYW1lPUdyb3VwMi54MTINCkNvbnRl"
			+ "bnQtVHJhbnNmZXItRW5jb2Rpbmc6IGJpbmFyeQ0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5l"
			+ "OyBmaWxlbmFtZT1Hcm91cDIueDEyDQoNCklTQSowMCpzc3Nzc3Nzc3NzKjAwKnJycnJycnJycnIqW"
			+ "loqQ1lDTE9ORSAgICAgICAgKlpaKlBBUlRORVIgICAgICAgICo5NjEwMDcqMjAxMypVKjAwMjAwKj"
			+ "AwMDAwMDAwMSowKlQqKg1HUypQTypTMVMxUzFTMVMxUzFTMVMqUjFSMVIxUjFSMVIxUjFSKjk2MTA"
			+ "wNyoyMDEzKjAwMDAwMDAwNCpYKjAwMzA1MA1TVCo4NTAqMDAwMDQwMDAxDUJFRyowMCpCRSoyYSo0"
			+ "MzMyNDIzNHY1NTIzKjk2MTAwNyoyM3RjNHZ5MjR2MmgzdmgzdmgqWloqSUVMKjA5KlJFKjA5DUNVU"
			+ "ioxMSpUUk4qNTY1Nio2NSo1NjYqSU1GKjAwNio5NjEwMDcNUkVGKjZBKjQzM3IxYzNyMzRyMzRjMz"
			+ "MxMnFjdGdjNTQqUmVmZXJlbmNlIE51bWJlcg1QRVIqQUEqSGFucyBHdXR0ZW4qQ1AqMS4zMjIuMzI"
			+ "zLjQ0NDQqKioqKnJnZzRlZ3Y0dDQNVEFYKjR0Z3RidDR0cjR0cipHTCpnaGdoKioqKioqKioqRypD"
			+ "DUZPQipUUCpDQSpVU0EqMDIqRE9NKkNDKlJlZ3VsYXIgTG9jYXRpb25zIHBlciBUZXJtcw1DVFAqR"
			+ "EUqQzA0KjQ1MyoyNTAwMCpEOSpTRUwqMjMyMTQqMjM0MzI0MjM0MjMqRVMqNDIyNDM0MjMNU0FDKk"
			+ "EqQjAwMCpBRSozNTQ1KjM0NDIzMDANQ1VSKjExKjc2Nyo3NzY3KjY1DVBPMSoxMTEtYWFhKjEwMDA"
			+ "wMDAqQVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRxNmYzNTM0djQzNTM0NTN2cTNxMzIqKioqKioq"
			+ "KioqKkExKnl0cmgNUE8xKjExMS1hYWEqMTAwMDAwMCpBUyo5MC4wMCpCRCpBSyoyMzQyMzV2MzUzN"
			+ "HE2ZjM1MzR2NDM1MzQ1M3ZxM3EzMioqKioqKioqKioqQTEqeXRyaA1QTzEqMTExLWFhYSoxMDAwMD"
			+ "AwKkFTKjkwLjAwKkJEKkFLKjIzNDIzNXYzNTM0cTZmMzUzNHY0MzUzNDUzdnEzcTMyKioqKioqKio"
			+ "qKipBMSp5dHJoDVBPMSoxMTEtYWFhKjEwMDAwMDAqQVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRx"
			+ "NmYzNTM0djQzNTM0NTN2cTNxMzIqKioqKioqKioqKkExKnl0cmgNUE8xKjExMS1hYWEqMTAwMDAwM"
			+ "CpBUyo5MC4wMCpCRCpBSyoyMzQyMzV2MzUzNHE2ZjM1MzR2NDM1MzQ1M3ZxM3EzMioqKioqKioqKi"
			+ "oqQTEqeXRyaA1QTzEqMTExLWFhYSoxMDAwMDAwKkFTKjkwLjAwKkJEKkFLKjIzNDIzNXYzNTM0cTZ"
			+ "mMzUzNHY0MzUzNDUzdnEzcTMyKioqKioqKioqKipBMSp5dHJoDVBPMSoxMTEtYWFhKjEwMDAwMDAq"
			+ "QVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRxNmYzNTM0djQzNTM0NTN2cTNxMzIqKioqKioqKioqK"
			+ "kExKnl0cmgNUE8xKjExMS1hYWEqMTAwMDAwMCpBUyo5MC4wMCpCRCpBSyoyMzQyMzV2MzUzNHE2Zj"
			+ "M1MzR2NDM1MzQ1M3ZxM3EzMioqKioqKioqKioqQTEqeXRyaA1QTzEqMTExLWFhYSoxMDAwMDAwKkF"
			+ "TKjkwLjAwKkJEKkFLKjIzNDIzNXYzNTM0cTZmMzUzNHY0MzUzNDUzdnEzcTMyKioqKioqKioqKipB"
			+ "MSp5dHJoDVBPMSoxMTEtYWFhKjEwMDAwMDAqQVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRxNmYzN"
			+ "TM0djQzNTM0NTN2cTNxMzIqKioqKioqKioqKkExKnl0cmgNQ1RUKjENU0UqMjIqMDAwMDQwMDAxDU"
			+ "dFKjEqMDAwMDAwMDA0DUlFQSoxKjAwMDAwMDAwMQ0=");

		[Test]
		public void TestWorkingData()
		{
			CmsCompressedData ed = new CmsCompressedData(compData);

			Assert.IsTrue(Arrays.AreEqual(uncompData, ed.GetContent()));
		}

		[Test]
		public void TestEach()
		{
			CmsCompressedData cd = GetStdData();

			Assert.IsTrue(Arrays.AreEqual(TEST_DATA, cd.GetContent()));
		}

		[Test]
		public void TestLimitUnder()
		{
			CmsCompressedData cd = GetStdData();

			try
			{
				cd.GetContent(TEST_DATA.Length / 2);
			}
			catch (CmsException e)
			{
				Assert.IsTrue(e.InnerException is StreamOverflowException);
			}
		}

		[Test]
		public void TestLimitOver()
		{
			CmsCompressedData cd = GetStdData();

			Assert.IsTrue(Arrays.AreEqual(TEST_DATA, cd.GetContent(TEST_DATA.Length * 2)));
		}

		[Test]
		public void TestLimitEqual()
		{
			CmsCompressedData cd = GetStdData();

			Assert.IsTrue(Arrays.AreEqual(TEST_DATA, cd.GetContent(TEST_DATA.Length)));
		}

		private CmsCompressedData GetStdData()
		{
			CmsProcessableByteArray testData = new CmsProcessableByteArray(TEST_DATA);
			CmsCompressedDataGenerator gen = new CmsCompressedDataGenerator();
			return gen.Generate(testData, CmsCompressedDataGenerator.ZLib);
		}
	}
}
