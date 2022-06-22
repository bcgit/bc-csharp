#if !LIB
using System;

using NUnit.Core;
using NUnit.Framework;

namespace Org.BouncyCastle.Math.Tests
{
    public class AllTests
    {
        [Suite]
        public static TestSuite Suite
        {
            get
            {
                TestSuite suite = new TestSuite("Math tests");
                suite.Add(new BigIntegerTest());
                suite.Add(new PrimesTest());
                return suite;
            }
        }
    }
}
#endif
