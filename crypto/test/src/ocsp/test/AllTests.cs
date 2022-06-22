#if !LIB
using System;

using NUnit.Core;
using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Ocsp.Tests
{
	public class AllTests
	{
        [Suite]
        public static TestSuite Suite
        {
            get
            {
                TestSuite suite = new TestSuite("OCSP Tests");
                suite.Add(new OcspTest());
                return suite;
            }
        }
	}
}
#endif
