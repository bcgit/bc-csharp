using System;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.UtilTests
{
    [TestFixture]
    public class LongsTest
    {
        [Test]
        public void TestNumberOfLeadingZeros()
        {
            for (int i = 0; i < 63; ++i)
            {
                Assert.AreEqual(i, Longs.NumberOfLeadingZeros((long)(0x8000000000000000UL >> i)));
                Assert.AreEqual(i, Longs.NumberOfLeadingZeros((long)(0xFFFFFFFFFFFFFFFFUL >> i)));
            }

            Assert.AreEqual(63, Longs.NumberOfLeadingZeros(1L));
            Assert.AreEqual(64, Longs.NumberOfLeadingZeros(0L));
        }

        [Test]
        public void TestNumberOfTrailingZeros()
        {
            for (int i = 0; i < 63; ++i)
            {
                Assert.AreEqual(i, Longs.NumberOfTrailingZeros(1L << i));
                Assert.AreEqual(i, Longs.NumberOfTrailingZeros(-1L << i));
            }

            Assert.AreEqual(63, Longs.NumberOfTrailingZeros(long.MinValue));
            Assert.AreEqual(64, Longs.NumberOfTrailingZeros(0L));
        }
    }
}
