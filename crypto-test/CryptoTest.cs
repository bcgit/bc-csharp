using System;

namespace crypto_test
{
	public class CryptoTest
	{
		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		static void Main(string[] args)
		{
			DateTime before = DateTime.Now;

			try
			{
				Org.BouncyCastle.Asn1.Tests.RegressionTest.Main(args);
				//Org.BouncyCastle.Bcpg.OpenPgp.Tests.Dsa2Test.?
				Org.BouncyCastle.Bcpg.OpenPgp.Tests.RegressionTest.Main(args);
				Org.BouncyCastle.Bcpg.OpenPgp.Examples.Tests.AllTests.Main(args);
				Org.BouncyCastle.Cms.Tests.AllTests.Main(args);
				Org.BouncyCastle.Crypto.Tests.RegressionTest.Main(args);
				Org.BouncyCastle.Crypto.IO.Tests.AllTests.Main(args);
				Org.BouncyCastle.Math.Tests.AllTests.Main(args);
				Org.BouncyCastle.Math.EC.Tests.AllTests.Main(args);
				Org.BouncyCastle.Ocsp.Tests.AllTests.Main(args);
				//Org.BouncyCastle.Pkcs.Tests.?
				Org.BouncyCastle.Pkcs.Tests.EncryptedPrivateKeyInfoTest.Main(args);
				Org.BouncyCastle.Pkcs.Tests.Pkcs10Test.Main(args);
				Org.BouncyCastle.Pkcs.Tests.Pkcs12StoreTest.Main(args);
				//Org.BouncyCastle.OpenSsl.Tests.?
				Org.BouncyCastle.OpenSsl.Tests.ReaderTest.Main(args);
				Org.BouncyCastle.OpenSsl.Tests.WriterTest.Main(args);
				//Org.BouncyCastle.Security.Tests.?
				Org.BouncyCastle.Tests.RegressionTest.Main(args);
				Org.BouncyCastle.Tsp.Tests.AllTests.Main(args);
				//Org.BouncyCastle.X509.Tests.?
			}
			catch (Exception e)
			{
				Console.WriteLine("Tests failed with exception: " + e.Message);
				Console.WriteLine(e.StackTrace);
			}

			DateTime after = DateTime.Now;
			long elapsedTicks = after.Ticks - before.Ticks;

			Console.WriteLine("Done in {0}ms.", elapsedTicks / TimeSpan.TicksPerMillisecond);
		}
	}
}
