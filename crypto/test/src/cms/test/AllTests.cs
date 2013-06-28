using System;

using NUnit.Core;
using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Cms.Tests
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
            TestSuite suite = new TestSuite("CMS Tests");

			suite.Add(new CompressedDataTest());
            suite.Add(new CompressedDataStreamTest());
			suite.Add(new EnvelopedDataTest());
			suite.Add(new EnvelopedDataStreamTest());
			suite.Add(new Rfc4134Test());
			suite.Add(new SignedDataTest());
			suite.Add(new SignedDataStreamTest());

			return suite;
        }
    }
}
