#if !LIB
using System;

using NUnit.Core;
using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Agreement.Tests
{
    [TestFixture]
    public class AllTests
    {
        [Suite]
        public static TestSuite Suite
        {
            get
            {
                TestSuite suite = new TestSuite("JPAKE Engine Tests");
                suite.Add(new JPakeParticipantTest());
                suite.Add(new JPakePrimeOrderGroupTest());
                suite.Add(new JPakeUtilitiesTest());
                return suite;
            }
        }
    }
}
#endif
