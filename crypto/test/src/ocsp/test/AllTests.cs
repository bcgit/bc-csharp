using System;

using NUnit.Core;
using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Ocsp.Tests
{
	public class AllTests
	{
		public static void Main(
			string[] args)
		{
			//junit.textui.TestRunner.run(suite());
			EventListener el = new NullListener();
			suite().Run(el);
		}

		public static TestSuite suite()
		{
			TestSuite suite = new TestSuite("OCSP Tests");

			suite.Add(new OcspTest());

			return suite;
		}
	}
}
