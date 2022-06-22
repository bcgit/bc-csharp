using System;
using System.Collections;
using System.IO;

#if !LIB
using NUnit.Core;
#endif
using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.IO.Pem.Tests
{
	[TestFixture]
	public class AllTests
	{
#if !LIB
        [Suite]
        public static TestSuite Suite
        {
            get
            {
                TestSuite suite = new TestSuite("PEM Utilities Tests");
                suite.Add(new AllTests());
                return suite;
            }
        }
#endif

        [Test]
		public void TestPemLength()
		{
			for (int i = 1; i != 60; i++)
			{
				lengthTest("CERTIFICATE", new ArrayList(), new byte[i]);
			}

			lengthTest("CERTIFICATE", new ArrayList(), new byte[100]);
			lengthTest("CERTIFICATE", new ArrayList(), new byte[101]);
			lengthTest("CERTIFICATE", new ArrayList(), new byte[102]);
			lengthTest("CERTIFICATE", new ArrayList(), new byte[103]);

			lengthTest("CERTIFICATE", new ArrayList(), new byte[1000]);
			lengthTest("CERTIFICATE", new ArrayList(), new byte[1001]);
			lengthTest("CERTIFICATE", new ArrayList(), new byte[1002]);
			lengthTest("CERTIFICATE", new ArrayList(), new byte[1003]);

			IList headers = new ArrayList();
			headers.Add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
			headers.Add(new PemHeader("DEK-Info", "DES3,0001020304050607"));
			lengthTest("RSA PRIVATE KEY", headers, new byte[103]);
		}

        [Test]
        public void TestMalformed()
        {
			try
			{
				PemReader rd = new PemReader(new StringReader("-----BEGIN \n"));
				rd.ReadPemObject();
				Assert.Fail("must fail on malformed");
			} catch (IOException ioex)
            {
				Assert.AreEqual("ran out of data before consuming type", ioex.Message);
            }

           
        }

		private void lengthTest(string type, IList headers, byte[] data)
		{
			StringWriter sw = new StringWriter();
			PemWriter pWrt = new PemWriter(sw);

			PemObject pemObj = new PemObject(type, headers, data);
			pWrt.WriteObject(pemObj);
			pWrt.Writer.Close();

			Assert.AreEqual(sw.ToString().Length, pWrt.GetOutputSize(pemObj));
		}
	}
}
