using System;

using NUnit.Core;
using NUnit.Framework;

namespace Org.BouncyCastle.Asn1.Tests
{
    public class AllTests
    {
        public static void Main(string[] args)
        {
//            junit.textui.TestRunner.run(suite());
            EventListener el = new NullListener();
            suite().Run(el);
        }

		public static TestSuite suite()
        {
            TestSuite suite = new TestSuite("ASN.1 tests");

			suite.Add(new AllTests());

			// TODO Add these tests to RegressionTest list
			suite.Add(new Asn1SequenceParserTest());
			suite.Add(new OctetStringTest());
			suite.Add(new ParseTest());
			suite.Add(new TimeTest());

			return suite;
        }
    }
}
