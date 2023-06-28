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

        [Test]
        public void TestPopCount()
        {
            Random random = new Random();

            for (int pos = 0; pos <= 24; ++pos)
            {
                int seed = Integers.RotateLeft(random.Next(0xFFFFFF) << 8, pos);
                ImplTestPopCountRange(seed, pos, 0xFF);
            }
        }

        private static void ImplTestPopCountRange(int seed, int pos, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                int n = seed + (i << pos);
                int expected = SimpleBitCount(n);
                Assert.AreEqual(expected, Integers.PopCount(n));
                Assert.AreEqual(expected, Integers.PopCount((uint)n));
            }
        }

        private static int SimpleBitCount(int n)
        {
            int count = 0;
            for (int i = 0; i < 32; ++i)
            {
                count += (n >> i) & 1;
            }
            return count;
        }
    }
}
