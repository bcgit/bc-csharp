#if !LIB
using System;

using NUnit.Core;
using NUnit.Framework;

namespace Org.BouncyCastle.Math.EC.Tests
{
    public class AllTests
    {
        [Suite]
        public static TestSuite Suite
        {
            get
            {
                TestSuite suite = new TestSuite("EC Math tests");
                suite.Add(new ECAlgorithmsTest());
                suite.Add(new ECPointTest());
                suite.Add(new FixedPointTest());
                return suite;
            }
        }
    }
}
#endif
