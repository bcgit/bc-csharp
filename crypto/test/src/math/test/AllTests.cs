using System;

using NUnit.Core;
using NUnit.Framework;

namespace Org.BouncyCastle.Math.Tests
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
			TestSuite suite = new TestSuite("Math tests");

			suite.Add(new BigIntegerTest());

			return suite;
        }
    }
}
