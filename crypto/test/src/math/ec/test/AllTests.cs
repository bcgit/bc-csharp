using System;

using NUnit.Core;
using NUnit.Framework;

namespace Org.BouncyCastle.Math.EC.Tests
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
			TestSuite suite = new TestSuite("EC Math tests");

			suite.Add(new ECPointTest());

			return suite;
        }
    }
}
