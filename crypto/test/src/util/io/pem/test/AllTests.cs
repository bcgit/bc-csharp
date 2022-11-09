using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.IO.Pem.Tests
{
	[TestFixture]
	public class AllTests
	{
        [Test]
		public void TestPemLength()
		{
			for (int i = 1; i != 60; i++)
			{
				LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[i]);
			}

			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[100]);
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[101]);
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[102]);
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[103]);

			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1000]);
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1001]);
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1002]);
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1003]);

			var headers = new List<PemHeader>();
			headers.Add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
			headers.Add(new PemHeader("DEK-Info", "DES3,0001020304050607"));
			LengthTest("RSA PRIVATE KEY", headers, new byte[103]);
		}

        [Test]
        public void TestMalformed()
        {
			try
			{
				using (var rd = new PemReader(new StringReader("-----BEGIN \n")))
				{
                    rd.ReadPemObject();
                }
                Assert.Fail("must fail on malformed");
			}
			catch (IOException ioex)
            {
				Assert.AreEqual("ran out of data before consuming type", ioex.Message);
            }
        }

		private void LengthTest(string type, IList<PemHeader> headers, byte[] data)
		{
            PemObject pemObj = new PemObject(type, headers, data);

            StringWriter sw = new StringWriter();

			using (var pWrt = new PemWriter(sw))
			{
                pWrt.WriteObject(pemObj);
                Assert.AreEqual(sw.ToString().Length, pWrt.GetOutputSize(pemObj));
            }
        }
	}
}
