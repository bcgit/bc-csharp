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

            for (int round = 0; round < 10; ++round)
            {
                int rand = random.Next() << 8;
                int init = SimpleBitCount(rand, 8, 32);

                for (int i = 0; i <= 0xFF; ++i)
                {
                    int pattern = rand | i;
                    int expected = init + SimpleBitCount(i, 0, 8);

                    for (int pos = 0; pos < 32; ++pos)
                    {
                        int input = Integers.RotateLeft(pattern, pos);

                        Assert.AreEqual(expected, Integers.PopCount(input));
                        Assert.AreEqual(expected, Integers.PopCount((uint)input));
                    }
                }
            }
        }

        private static int SimpleBitCount(int n, int lo, int hi)
        {
            int count = 0;
            for (int i = lo; i < hi; ++i)
            {
                count += (n >> i) & 1;
            }
            return count;
        }
    }
}
