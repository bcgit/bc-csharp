using System;

using NUnit.Core;
using NUnit.Framework;

namespace Org.BouncyCastle.Crypto.IO.Tests
{
	public class AllTests
	{
		public static void Main(
			string[] args)
		{
//            junit.textui.TestRunner.run(suite());
			EventListener el = new NullListener();
			suite().Run(el);
		}

		public static TestSuite suite()
		{
			TestSuite suite = new TestSuite("IO tests");

			suite.Add(new CipherStreamTest());

			return suite;
		}
	}
}
