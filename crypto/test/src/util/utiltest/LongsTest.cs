using System;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.UtilTests
{
    [TestFixture]
    public class LongsTest
    {
        [Test]
        public void HighestOneBit()
        {
            for (int i = 0; i < 63; ++i)
            {
                Assert.AreEqual(1L << (63 - i), Longs.HighestOneBit((long)(0x8000000000000000UL >> i)));
                Assert.AreEqual(1L << (63 - i), Longs.HighestOneBit((long)(0xFFFFFFFFFFFFFFFFUL >> i)));
            }

            Assert.AreEqual(1L, Longs.HighestOneBit(1L));
            Assert.AreEqual(0L, Longs.HighestOneBit(0L));
        }

        [Test]
        public void LowestOneBit()
        {
            for (int i = 0; i < 63; ++i)
            {
                Assert.AreEqual(1L << i, Longs.LowestOneBit((long)(0x0000000000000001UL << i)));
                Assert.AreEqual(1L << i, Longs.LowestOneBit((long)(0xFFFFFFFFFFFFFFFFUL << i)));
            }

            Assert.AreEqual(1L, Longs.LowestOneBit(1L));
            Assert.AreEqual(0L, Longs.LowestOneBit(0L));
        }

        [Test]
        public void NumberOfLeadingZeros()
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
        public void NumberOfTrailingZeros()
        {
            for (int i = 0; i < 63; ++i)
            {
                Assert.AreEqual(i, Longs.NumberOfTrailingZeros(1L << i));
                Assert.AreEqual(i, Longs.NumberOfTrailingZeros(-1L << i));
            }

            Assert.AreEqual(63, Longs.NumberOfTrailingZeros(long.MinValue));
            Assert.AreEqual(64, Longs.NumberOfTrailingZeros(0L));
        }

        [Test]
        public void PopCount()
        {
            Random random = new Random();

            for (int round = 0; round < 10; ++round)
            {
                long rand = ((long)random.Next() << 36) ^ ((long)random.Next() << 8);
                int init = SimpleBitCount(rand, 8, 64);

                for (long i = 0; i <= 0xFFL; ++i)
                {
                    long pattern = rand | i;
                    int expected = init + SimpleBitCount(i, 0, 8);

                    for (int pos = 0; pos < 64; ++pos)
                    {
                        long input = Longs.RotateLeft(pattern, pos);

                        Assert.AreEqual(expected, Longs.PopCount(input));
                        Assert.AreEqual(expected, Longs.PopCount((ulong)input));
                    }
                }
            }
        }

        private static int SimpleBitCount(long n, int lo, int hi)
        {
            long count = 0;
            for (int i = lo; i < hi; ++i)
            {
                count += (n >> i) & 1L;
            }
            return (int)count;
        }
    }
}
