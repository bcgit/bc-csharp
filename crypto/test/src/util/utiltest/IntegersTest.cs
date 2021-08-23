using System;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.UtilTests
{
    [TestFixture]
    public class IntegersTest
    {
        [Test]
        public void TestNumberOfLeadingZeros()
        {
            for (int i = 0; i < 31; ++i)
            {
                Assert.AreEqual(i, Integers.NumberOfLeadingZeros((int)(0x80000000U >> i)));
                Assert.AreEqual(i, Integers.NumberOfLeadingZeros((int)(0xFFFFFFFFU >> i)));
            }

            Assert.AreEqual(31, Integers.NumberOfLeadingZeros(1));
            Assert.AreEqual(32, Integers.NumberOfLeadingZeros(0));
        }

        [Test]
        public void TestNumberOfTrailingZeros()
        {
            for (int i = 0; i < 31; ++i)
            {
                Assert.AreEqual(i, Integers.NumberOfTrailingZeros(1 << i));
                Assert.AreEqual(i, Integers.NumberOfTrailingZeros(-1 << i));
            }

            Assert.AreEqual(31, Integers.NumberOfTrailingZeros(int.MinValue));
            Assert.AreEqual(32, Integers.NumberOfTrailingZeros(0));
        }
    }
}
