using System;
#if !NET8_0_OR_GREATER
using System.Runtime.Serialization.Formatters.Binary;
#endif

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Math.Tests
{
    [TestFixture]
    public class BigIntegerTest
    {
        private static readonly Random random = new Random();

        [Test]
        public void MonoBug81857()
        {
            BigInteger b = new BigInteger("18446744073709551616");
            BigInteger mod = new BigInteger("48112959837082048697");
            BigInteger expected = new BigInteger("4970597831480284165");

            BigInteger byMultiply = b.Multiply(b).Mod(mod);
            Assert.AreEqual(expected, byMultiply, "b * b % mod");

            BigInteger bySquare = b.Square().Mod(mod);
            Assert.AreEqual(expected, bySquare, "b^2 % mod");

            BigInteger byModPow = b.ModPow(BigInteger.Two, mod);
            Assert.AreEqual(expected, byModPow, "b.ModPow(2, mod)");
        }

        [Test]
        public void TestAbs()
        {
            Assert.AreEqual(Zero, Zero.Abs());

            Assert.AreEqual(One, One.Abs());
            Assert.AreEqual(One, MinusOne.Abs());

            Assert.AreEqual(Two, Two.Abs());
            Assert.AreEqual(Two, MinusTwo.Abs());
        }

        [Test]
        public void TestAdd()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(
                        Val(i + j),
                        Val(i).Add(Val(j)),
                        "Problem: " + i + ".Add(" + j + ") should be " + (i + j));
                }
            }
        }

        [Test]
        public void TestAnd()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(
                        Val(i & j),
                        Val(i).And(Val(j)),
                        "Problem: " + i + " AND " + j + " should be " + (i & j));
                }
            }
        }

        [Test]
        public void TestAndNot()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(
                        Val(i & ~j),
                        Val(i).AndNot(Val(j)),
                        "Problem: " + i + " AND NOT " + j + " should be " + (i & ~j));
                }
            }
        }

        [Test]
        public void TestBitCount()
        {
            Assert.AreEqual(0, Zero.BitCount);
            Assert.AreEqual(1, One.BitCount);
            Assert.AreEqual(0, MinusOne.BitCount);
            Assert.AreEqual(1, Two.BitCount);
            Assert.AreEqual(1, MinusTwo.BitCount);

            for (int i = 0; i < 100; ++i)
            {
                BigInteger pow2 = One.ShiftLeft(i);

                Assert.AreEqual(1, pow2.BitCount);
                Assert.AreEqual(i, pow2.Negate().BitCount);
            }

            for (int i = 0; i < 10; ++i)
            {
                BigInteger test = new BigInteger(128, 0, random);
                int bitCount = 0;

                for (int bit = 0; bit < test.BitLength; ++bit)
                {
                    if (test.TestBit(bit))
                    {
                        ++bitCount;
                    }
                }

                Assert.AreEqual(bitCount, test.BitCount);
            }
        }

        [Test]
        public void TestBitLength()
        {
            Assert.AreEqual(0, Zero.BitLength);
            Assert.AreEqual(1, One.BitLength);
            Assert.AreEqual(0, MinusOne.BitLength);
            Assert.AreEqual(2, Two.BitLength);
            Assert.AreEqual(1, MinusTwo.BitLength);

            for (int i = 0; i < 100; ++i)
            {
                int bit = i + random.Next(64);
                BigInteger odd = new BigInteger(bit, random).SetBit(bit + 1).SetBit(0);
                BigInteger pow2 = One.ShiftLeft(bit);

                Assert.AreEqual(bit + 2, odd.BitLength);
                Assert.AreEqual(bit + 2, odd.Negate().BitLength);
                Assert.AreEqual(bit + 1, pow2.BitLength);
                Assert.AreEqual(bit, pow2.Negate().BitLength);
            }
        }

        [Test]
        public void TestClearBit()
        {
            Assert.AreEqual(Zero, Zero.ClearBit(0));
            Assert.AreEqual(Zero, One.ClearBit(0));
            Assert.AreEqual(Two, Two.ClearBit(0));

            Assert.AreEqual(Zero, Zero.ClearBit(1));
            Assert.AreEqual(One, One.ClearBit(1));
            Assert.AreEqual(Zero, Two.ClearBit(1));

            // TODO Tests for clearing bits in negative numbers

            // TODO Tests for clearing extended bits

            for (int i = 0; i < 10; ++i)
            {
                BigInteger n = new BigInteger(128, random);

                for (int j = 0; j < 10; ++j)
                {
                    int pos = random.Next(128);
                    BigInteger m = n.ClearBit(pos);
                    bool test = m.ShiftRight(pos).Remainder(Two).Equals(One);

                    Assert.IsFalse(test);
                }
            }

            for (int i = 0; i < 100; ++i)
            {
                BigInteger pow2 = One.ShiftLeft(i);
                BigInteger minusPow2 = pow2.Negate();

                Assert.AreEqual(Zero, pow2.ClearBit(i));
                Assert.AreEqual(minusPow2.ShiftLeft(1), minusPow2.ClearBit(i));

                BigInteger bigI = BigInteger.ValueOf(i);
                BigInteger negI = bigI.Negate();

                for (int j = 0; j < 10; ++j)
                {
                    string data = "i=" + i + ", j=" + j;
                    Assert.AreEqual(bigI.AndNot(One.ShiftLeft(j)), bigI.ClearBit(j), data);
                    Assert.AreEqual(negI.AndNot(One.ShiftLeft(j)), negI.ClearBit(j), data);
                }
            }
        }

        [Test]
        public void TestCompareTo()
        {
            Assert.AreEqual(0, MinusTwo.CompareTo(MinusTwo));
            Assert.AreEqual(-1, MinusTwo.CompareTo(MinusOne));
            Assert.AreEqual(-1, MinusTwo.CompareTo(Zero));
            Assert.AreEqual(-1, MinusTwo.CompareTo(One));
            Assert.AreEqual(-1, MinusTwo.CompareTo(Two));

            Assert.AreEqual(1, MinusOne.CompareTo(MinusTwo));
            Assert.AreEqual(0, MinusOne.CompareTo(MinusOne));
            Assert.AreEqual(-1, MinusOne.CompareTo(Zero));
            Assert.AreEqual(-1, MinusOne.CompareTo(One));
            Assert.AreEqual(-1, MinusOne.CompareTo(Two));

            Assert.AreEqual(1, Zero.CompareTo(MinusTwo));
            Assert.AreEqual(1, Zero.CompareTo(MinusOne));
            Assert.AreEqual(0, Zero.CompareTo(Zero));
            Assert.AreEqual(-1, Zero.CompareTo(One));
            Assert.AreEqual(-1, Zero.CompareTo(Two));

            Assert.AreEqual(1, One.CompareTo(MinusTwo));
            Assert.AreEqual(1, One.CompareTo(MinusOne));
            Assert.AreEqual(1, One.CompareTo(Zero));
            Assert.AreEqual(0, One.CompareTo(One));
            Assert.AreEqual(-1, One.CompareTo(Two));

            Assert.AreEqual(1, Two.CompareTo(MinusTwo));
            Assert.AreEqual(1, Two.CompareTo(MinusOne));
            Assert.AreEqual(1, Two.CompareTo(Zero));
            Assert.AreEqual(1, Two.CompareTo(One));
            Assert.AreEqual(0, Two.CompareTo(Two));
        }

        [Test]
        public void TestConstructors()
        {
            Assert.AreEqual(BigInteger.Zero, new BigInteger(new byte[]{ 0 }));
            Assert.AreEqual(BigInteger.Zero, new BigInteger(new byte[]{ 0, 0 }));

            for (int i = 0; i < 10; ++i)
            {
                Assert.IsTrue(new BigInteger(i + 3, 0, random).TestBit(0));
            }

            // TODO Other constructors
        }

        [Test]
        public void TestDivide()
        {
            for (int i = -5; i <= 5; ++i)
            {
                try
                {
                    Val(i).Divide(Zero);
                    Assert.Fail("expected ArithmeticException");
                }
                catch (ArithmeticException) {}
            }

            int product = 1 * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9;
            int productPlus = product + 1;

            BigInteger bigProduct = Val(product);
            BigInteger bigProductPlus = Val(productPlus);

            for (int divisor = 1; divisor < 10; ++divisor)
            {
                // Exact division
                BigInteger expected = Val(product / divisor);

                Assert.AreEqual(expected, bigProduct.Divide(Val(divisor)));
                Assert.AreEqual(expected.Negate(), bigProduct.Negate().Divide(Val(divisor)));
                Assert.AreEqual(expected.Negate(), bigProduct.Divide(Val(divisor).Negate()));
                Assert.AreEqual(expected, bigProduct.Negate().Divide(Val(divisor).Negate()));

                expected = Val((product + 1)/divisor);

                Assert.AreEqual(expected, bigProductPlus.Divide(Val(divisor)));
                Assert.AreEqual(expected.Negate(), bigProductPlus.Negate().Divide(Val(divisor)));
                Assert.AreEqual(expected.Negate(), bigProductPlus.Divide(Val(divisor).Negate()));
                Assert.AreEqual(expected, bigProductPlus.Negate().Divide(Val(divisor).Negate()));
            }

            for (int rep = 0; rep < 10; ++rep)
            {
                BigInteger a = new BigInteger(100 - rep, 0, random);
                BigInteger b = new BigInteger(100 + rep, 0, random);
                BigInteger c = new BigInteger(10 + rep, 0, random);
                BigInteger d = a.Multiply(b).Add(c);
                BigInteger e = d.Divide(a);

                Assert.AreEqual(b, e);
            }

            // Special tests for power of two since uses different code path internally
            for (int i = 0; i < 100; ++i)
            {
                int shift = random.Next(64);
                BigInteger a = One.ShiftLeft(shift);
                BigInteger b = new BigInteger(64 + random.Next(64), random);
                BigInteger bShift = b.ShiftRight(shift);

                string data = "shift=" + shift +", b=" + b.ToString(16);

                Assert.AreEqual(bShift, b.Divide(a), data);
                Assert.AreEqual(bShift.Negate(), b.Divide(a.Negate()), data);
                Assert.AreEqual(bShift.Negate(), b.Negate().Divide(a), data);
                Assert.AreEqual(bShift, b.Negate().Divide(a.Negate()), data);
            }

            // Regression
            {
                int shift = 63;
                BigInteger a = One.ShiftLeft(shift);
                BigInteger b = new BigInteger(1, Hex.Decode("2504b470dc188499"));
                BigInteger bShift = b.ShiftRight(shift);

                string data = "shift=" + shift +", b=" + b.ToString(16);

                Assert.AreEqual(bShift, b.Divide(a), data);
                Assert.AreEqual(bShift.Negate(), b.Divide(a.Negate()), data);
//				Assert.AreEqual(bShift.Negate(), b.Negate().Divide(a), data);
                Assert.AreEqual(bShift, b.Negate().Divide(a.Negate()), data);
            }
        }

        [Test]
        public void TestDivideAndRemainder()
        {
            // TODO More basic tests

            BigInteger n = new BigInteger(48, random);
            BigInteger[] qr = n.DivideAndRemainder(n);
            Assert.AreEqual(One, qr[0]);
            Assert.AreEqual(Zero, qr[1]);
            qr = n.DivideAndRemainder(One);
            Assert.AreEqual(n, qr[0]);
            Assert.AreEqual(Zero, qr[1]);

            for (int rep = 0; rep < 10; ++rep)
            {
                BigInteger a = new BigInteger(100 - rep, 0, random);
                BigInteger b = new BigInteger(100 + rep, 0, random);
                BigInteger c = new BigInteger(10 + rep, 0, random);
                BigInteger d = a.Multiply(b).Add(c);
                BigInteger[] es = d.DivideAndRemainder(a);

                Assert.AreEqual(b, es[0]);
                Assert.AreEqual(c, es[1]);
            }

            // Special tests for power of two since uses different code path internally
            for (int i = 0; i < 100; ++i)
            {
                int shift = random.Next(64);
                BigInteger a = One.ShiftLeft(shift);
                BigInteger b = new BigInteger(64 + random.Next(64), random);
                BigInteger bShift = b.ShiftRight(shift);
                BigInteger bMod = b.And(a.Subtract(One));

                string data = "shift=" + shift +", b=" + b.ToString(16);

                qr = b.DivideAndRemainder(a);
                Assert.AreEqual(bShift, qr[0], data);
                Assert.AreEqual(bMod, qr[1], data);

                qr = b.DivideAndRemainder(a.Negate());
                Assert.AreEqual(bShift.Negate(), qr[0], data);
                Assert.AreEqual(bMod, qr[1], data);

                qr = b.Negate().DivideAndRemainder(a);
                Assert.AreEqual(bShift.Negate(), qr[0], data);
                Assert.AreEqual(bMod.Negate(), qr[1], data);

                qr = b.Negate().DivideAndRemainder(a.Negate());
                Assert.AreEqual(bShift, qr[0], data);
                Assert.AreEqual(bMod.Negate(), qr[1], data);
            }
        }

        [Test]
        public void TestFlipBit()
        {
            for (int i = 0; i < 10; ++i)
            {
                BigInteger a = new BigInteger(128, 0, random);
                BigInteger b = a;

                for (int x = 0; x < 100; ++x)
                {
                    // Note: Intentionally greater than initial size
                    int pos = random.Next(256);

                    a = a.FlipBit(pos);
                    b = b.TestBit(pos) ? b.ClearBit(pos) : b.SetBit(pos);
                }

                Assert.AreEqual(a, b);
            }

            for (int i = 0; i < 100; ++i)
            {
                BigInteger pow2 = One.ShiftLeft(i);
                BigInteger minusPow2 = pow2.Negate();

                Assert.AreEqual(Zero, pow2.FlipBit(i));
                Assert.AreEqual(minusPow2.ShiftLeft(1), minusPow2.FlipBit(i));

                BigInteger bigI = BigInteger.ValueOf(i);
                BigInteger negI = bigI.Negate();

                for (int j = 0; j < 10; ++j)
                {
                    string data = "i=" + i + ", j=" + j;
                    Assert.AreEqual(bigI.Xor(One.ShiftLeft(j)), bigI.FlipBit(j), data);
                    Assert.AreEqual(negI.Xor(One.ShiftLeft(j)), negI.FlipBit(j), data);
                }
            }
        }

        [Test]
        public void TestGcd()
        {
            for (int i = 0; i < 10; ++i)
            {
                BigInteger fac = new BigInteger(32, random).Add(Two);
                BigInteger p1 = BigInteger.ProbablePrime(63, random);
                BigInteger p2 = BigInteger.ProbablePrime(64, random);

                BigInteger gcd = fac.Multiply(p1).Gcd(fac.Multiply(p2));

                Assert.AreEqual(fac, gcd);
            }
        }

        [Test]
        public void TestGetLowestSetBit()
        {
            for (int i = 1; i <= 100; ++i)
            {
                BigInteger test = new BigInteger(i + 1, 0, random).Add(One);
                int bit1 = test.GetLowestSetBit();
                Assert.AreEqual(test, test.ShiftRight(bit1).ShiftLeft(bit1));
                int bit2 = test.ShiftLeft(i + 1).GetLowestSetBit();
                Assert.AreEqual(i + 1, bit2 - bit1);
                int bit3 = test.ShiftLeft(3 * i).GetLowestSetBit();
                Assert.AreEqual(3 * i, bit3 - bit1);
            }
        }

        [Test]
        public void TestIntValue()
        {
            int[] tests = new int[]{ int.MinValue, -1234, -10, -1, 0, ~0, 1, 10, 5678, int.MaxValue };

            foreach (int test in tests)
            {
                Assert.AreEqual(test, Val(test).IntValue);
            }

            // TODO Tests for large numbers
        }

        [Test]
        public void TestIsProbablePrime()
        {
            Assert.IsFalse(Zero.IsProbablePrime(100));
            Assert.IsFalse(Zero.IsProbablePrime(100));
            Assert.IsTrue(Zero.IsProbablePrime(0));
            Assert.IsTrue(Zero.IsProbablePrime(-10));
            Assert.IsFalse(MinusOne.IsProbablePrime(100));
            Assert.IsTrue(MinusTwo.IsProbablePrime(100));
            Assert.IsTrue(Val(-17).IsProbablePrime(100));
            Assert.IsTrue(Val(67).IsProbablePrime(100));
            Assert.IsTrue(Val(773).IsProbablePrime(100));

            foreach (int p in FirstPrimes)
            {
                Assert.IsTrue(Val(p).IsProbablePrime(100));
                Assert.IsTrue(Val(-p).IsProbablePrime(100));
            }

            foreach (int c in NonPrimes)
            {
                Assert.IsFalse(Val(c).IsProbablePrime(100));
                Assert.IsFalse(Val(-c).IsProbablePrime(100));
            }

            foreach (int e in MersennePrimeExponents)
            {
                Assert.IsTrue(Mersenne(e).IsProbablePrime(100));
                Assert.IsTrue(Mersenne(e).Negate().IsProbablePrime(100));
            }

            foreach (int e in NonPrimeExponents)
            {
                Assert.IsFalse(Mersenne(e).IsProbablePrime(100));
                Assert.IsFalse(Mersenne(e).Negate().IsProbablePrime(100));
            }

            // TODO Other examples of 'tricky' values?
        }

        [Test]
        public void TestLongValue()
        {
            long[] tests = new long[]{ long.MinValue, -1234, -10, -1, 0L, ~0L, 1, 10, 5678, long.MaxValue };

            foreach (long test in tests)
            {
                Assert.AreEqual(test, Val(test).LongValue);
            }

            // TODO Tests for large numbers
        }

        [Test]
        public void TestMax()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(Val(System.Math.Max(i, j)), Val(i).Max(Val(j)));
                }
            }
        }

        [Test]
        public void TestMin()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(Val(System.Math.Min(i, j)), Val(i).Min(Val(j)));
                }
            }
        }

        [Test]
        public void TestMod()
        {
            // TODO Basic tests

            for (int rep = 0; rep < 100; ++rep)
            {
                int diff = random.Next(25);
                BigInteger a = new BigInteger(100 - diff, 0, random);
                BigInteger b = new BigInteger(100 + diff, 0, random);
                BigInteger c = new BigInteger(10 + diff, 0, random);

                BigInteger d = a.Multiply(b).Add(c);
                BigInteger e = d.Mod(a);
                Assert.AreEqual(c, e);

                BigInteger pow2 = One.ShiftLeft(random.Next(128));
                Assert.AreEqual(b.And(pow2.Subtract(One)), b.Mod(pow2));
            }
        }

        [Test]
        public void TestModInverse()
        {
            for (int i = 0; i < 10; ++i)
            {
                BigInteger p = BigInteger.ProbablePrime(64, random);
                BigInteger q = new BigInteger(63, random).Add(One);
                BigInteger inv = q.ModInverse(p);
                BigInteger inv2 = inv.ModInverse(p);

                Assert.AreEqual(q, inv2);
                Assert.AreEqual(One, q.Multiply(inv).Mod(p));
            }

            // ModInverse a power of 2 for a range of powers
            for (int i = 1; i <= 128; ++i)
            {
                BigInteger m = One.ShiftLeft(i);
                BigInteger d = new BigInteger(i, random).SetBit(0);
                BigInteger x = d.ModInverse(m);
                BigInteger check = x.Multiply(d).Mod(m);

                Assert.AreEqual(One, check);
            }
        }

        [Test]
        public void TestModPow()
        {
            try
            {
                Two.ModPow(One, Zero);
                Assert.Fail("expected ArithmeticException");
            }
            catch (ArithmeticException) {}

            Assert.AreEqual(Zero, Zero.ModPow(Zero, One));
            Assert.AreEqual(One, Zero.ModPow(Zero, Two));
            Assert.AreEqual(Zero, Two.ModPow(One, One));
            Assert.AreEqual(One, Two.ModPow(Zero, Two));

            for (int i = 0; i < 100; ++i)
            {
                BigInteger m = BigInteger.ProbablePrime(10 + i, random);
                BigInteger x = new BigInteger(m.BitLength - 1, random);

                Assert.AreEqual(x, x.ModPow(m, m));
                if (x.SignValue != 0)
                {
                    Assert.AreEqual(Zero, Zero.ModPow(x, m));
                    Assert.AreEqual(One, x.ModPow(m.Subtract(One), m));
                }

                BigInteger y = new BigInteger(m.BitLength - 1, random);
                BigInteger n = new BigInteger(m.BitLength - 1, random);
                BigInteger n3 = n.ModPow(Three, m);

                BigInteger resX = n.ModPow(x, m);
                BigInteger resY = n.ModPow(y, m);
                BigInteger res = resX.Multiply(resY).Mod(m);
                BigInteger res3 = res.ModPow(Three, m);

                Assert.AreEqual(res3, n3.ModPow(x.Add(y), m));

                BigInteger a = x.Add(One); // Make sure it's not zero
                BigInteger b = y.Add(One); // Make sure it's not zero

                Assert.AreEqual(a.ModPow(b, m).ModInverse(m), a.ModPow(b.Negate(), m));
            }
        }

        [Test]
        public void TestMultiply()
        {
            BigInteger one = BigInteger.One;

            Assert.AreEqual(one, one.Negate().Multiply(one.Negate()));

            for (int i = 0; i < 100; ++i)
            {
                int aLen = 64 + random.Next(64);
                int bLen = 64 + random.Next(64);

                BigInteger a = new BigInteger(aLen, random).SetBit(aLen);
                BigInteger b = new BigInteger(bLen, random).SetBit(bLen);
                BigInteger c = new BigInteger(32, random);

                BigInteger ab = a.Multiply(b);
                BigInteger bc = b.Multiply(c);

                Assert.AreEqual(ab.Add(bc), a.Add(c).Multiply(b));
                Assert.AreEqual(ab.Subtract(bc), a.Subtract(c).Multiply(b));
            }

            // Special tests for power of two since uses different code path internally
            for (int i = 0; i < 100; ++i)
            {
                int shift = random.Next(64);
                BigInteger a = one.ShiftLeft(shift);
                BigInteger b = new BigInteger(64 + random.Next(64), random);
                BigInteger bShift = b.ShiftLeft(shift);

                Assert.AreEqual(bShift, a.Multiply(b));
                Assert.AreEqual(bShift.Negate(), a.Multiply(b.Negate()));
                Assert.AreEqual(bShift.Negate(), a.Negate().Multiply(b));
                Assert.AreEqual(bShift, a.Negate().Multiply(b.Negate()));

                Assert.AreEqual(bShift, b.Multiply(a));
                Assert.AreEqual(bShift.Negate(), b.Multiply(a.Negate()));
                Assert.AreEqual(bShift.Negate(), b.Negate().Multiply(a));
                Assert.AreEqual(bShift, b.Negate().Multiply(a.Negate()));
            }
        }

        [Test]
        public void TestNegate()
        {
            for (int i = -10; i <= 10; ++i)
            {
                Assert.AreEqual(Val(-i), Val(i).Negate());
            }
        }

        [Test]
        public void TestNextProbablePrime()
        {
            BigInteger firstPrime = BigInteger.ProbablePrime(32, random);
            BigInteger nextPrime = firstPrime.NextProbablePrime();

            Assert.IsTrue(firstPrime.IsProbablePrime(10));
            Assert.IsTrue(nextPrime.IsProbablePrime(10));

            BigInteger check = firstPrime.Add(One);

            while (check.CompareTo(nextPrime) < 0)
            {
                Assert.IsFalse(check.IsProbablePrime(10));
                check = check.Add(One);
            }
        }

        [Test]
        public void TestNot()
        {
            for (int i = -10; i <= 10; ++i)
            {
                Assert.AreEqual(
                    Val(~i),
                    Val(i).Not(),
                    "Problem: ~" + i + " should be " + ~i);
            }
        }

        [Test]
        public void TestOr()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(
                        Val(i | j),
                        Val(i).Or(Val(j)),
                        "Problem: " + i + " OR " + j + " should be " + (i | j));
                }
            }
        }

        [Test]
        public void TestPow()
        {
            Assert.AreEqual(One, Zero.Pow(0));
            Assert.AreEqual(Zero, Zero.Pow(123));
            Assert.AreEqual(One, One.Pow(0));
            Assert.AreEqual(One, One.Pow(123));

            Assert.AreEqual(Two.Pow(147), One.ShiftLeft(147));
            Assert.AreEqual(One.ShiftLeft(7).Pow(11), One.ShiftLeft(77));

            BigInteger n = new BigInteger("1234567890987654321");
            BigInteger result = One;

            for (int i = 0; i < 10; ++i)
            {
                try
                {
                    Val(i).Pow(-1);
                    Assert.Fail("expected ArithmeticException");
                }
                catch (ArithmeticException) {}

                Assert.AreEqual(result, n.Pow(i));

                result = result.Multiply(n);
            }
        }

        [Test]
        public void TestRemainder()
        {
            // TODO Basic tests

            for (int rep = 0; rep < 10; ++rep)
            {
                BigInteger a = new BigInteger(100 - rep, 0, random);
                BigInteger b = new BigInteger(100 + rep, 0, random);
                BigInteger c = new BigInteger(10 + rep, 0, random);
                BigInteger d = a.Multiply(b).Add(c);
                BigInteger e = d.Remainder(a);

                Assert.AreEqual(c, e);
            }
        }

#if !NET8_0_OR_GREATER // BinaryFormatter no longer supported
        [Test]
        public void TestSerialization()
        {
            using (var buf = new System.IO.MemoryStream())
            {
                BigInteger x = new BigInteger(128, random);
                object y;

#pragma warning disable SYSLIB0011 // Type or member is obsolete
                var formatter = new BinaryFormatter();
                formatter.Serialize(buf, x);

                buf.Position = 0;
                y = formatter.Deserialize(buf);
#pragma warning restore SYSLIB0011 // Type or member is obsolete

                Assert.AreEqual(buf.Length, buf.Position);
                Assert.AreEqual(x, y);
            }
        }
#endif

        [Test]
        public void TestSetBit()
        {
            Assert.AreEqual(One, Zero.SetBit(0));
            Assert.AreEqual(One, One.SetBit(0));
            Assert.AreEqual(Three, Two.SetBit(0));

            Assert.AreEqual(Two, Zero.SetBit(1));
            Assert.AreEqual(Three, One.SetBit(1));
            Assert.AreEqual(Two, Two.SetBit(1));

            // TODO Tests for setting bits in negative numbers

            // TODO Tests for setting extended bits

            for (int i = 0; i < 10; ++i)
            {
                BigInteger n = new BigInteger(128, random);

                for (int j = 0; j < 10; ++j)
                {
                    int pos = random.Next(128);
                    BigInteger m = n.SetBit(pos);
                    bool test = m.ShiftRight(pos).Remainder(Two).Equals(One);

                    Assert.IsTrue(test);
                }
            }

            for (int i = 0; i < 100; ++i)
            {
                BigInteger pow2 = One.ShiftLeft(i);
                BigInteger minusPow2 = pow2.Negate();

                Assert.AreEqual(pow2, pow2.SetBit(i));
                Assert.AreEqual(minusPow2, minusPow2.SetBit(i));

                BigInteger bigI = BigInteger.ValueOf(i);
                BigInteger negI = bigI.Negate();

                for (int j = 0; j < 10; ++j)
                {
                    string data = "i=" + i + ", j=" + j;
                    Assert.AreEqual(bigI.Or(One.ShiftLeft(j)), bigI.SetBit(j), data);
                    Assert.AreEqual(negI.Or(One.ShiftLeft(j)), negI.SetBit(j), data);
                }
            }
        }

        [Test]
        public void TestShiftLeft()
        {
            for (int i = 0; i < 100; ++i)
            {
                int shift = random.Next(128);

                BigInteger a = new BigInteger(128 + i, random).Add(One);
                int aBits = a.BitCount; // Make sure nBits is set
                Assert.LessOrEqual(aBits, 128 + i + 1);

                BigInteger negA = a.Negate();
                int negABits = negA.BitCount; // Make sure nBits is set
                Assert.LessOrEqual(negABits, 128 + i + 1);

                BigInteger b = a.ShiftLeft(shift);
                BigInteger c = negA.ShiftLeft(shift);

                Assert.AreEqual(a.BitCount, b.BitCount);
                Assert.AreEqual(negA.BitCount + shift, c.BitCount);
                Assert.AreEqual(a.BitLength + shift, b.BitLength);
                Assert.AreEqual(negA.BitLength + shift, c.BitLength);

                int j = 0;
                for (; j < shift; ++j)
                {
                    Assert.IsFalse(b.TestBit(j));
                }

                for (; j < b.BitLength; ++j)
                {
                    Assert.AreEqual(a.TestBit(j - shift), b.TestBit(j));
                }
            }
        }

        [Test]
        public void TestShiftRight()
        {
            for (int i = 0; i < 10; ++i)
            {
                int shift = random.Next(128);
                BigInteger a = new BigInteger(256 + i, random).SetBit(256 + i);
                BigInteger b = a.ShiftRight(shift);

                Assert.AreEqual(a.BitLength - shift, b.BitLength);

                for (int j = 0; j < b.BitLength; ++j)
                {
                    Assert.AreEqual(a.TestBit(j + shift), b.TestBit(j));
                }
            }
        }

        [Test]
        public void TestSignValue()
        {
            for (int i = -10; i <= 10; ++i)
            {
                Assert.AreEqual(i < 0 ? -1 : i > 0 ? 1 : 0, Val(i).SignValue);
            }
        }

        [Test]
        public void TestSubtract()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(
                        Val(i - j),
                        Val(i).Subtract(Val(j)),
                        "Problem: " + i + ".Subtract(" + j + ") should be " + (i - j));
                }
            }
        }

        [Test]
        public void TestTestBit()
        {
            for (int i = 0; i < 10; ++i)
            {
                BigInteger n = new BigInteger(128, random);

                Assert.IsFalse(n.TestBit(128));
                Assert.IsTrue(n.Negate().TestBit(128));

                for (int j = 0; j < 10; ++j)
                {
                    int pos = random.Next(128);
                    bool test = n.ShiftRight(pos).Remainder(Two).Equals(One);

                    Assert.AreEqual(test, n.TestBit(pos));
                }
            }
        }

        [Test]
        public void TestToByteArray()
        {
            byte[] z = BigInteger.Zero.ToByteArray();
            Assert.IsTrue(Arrays.AreEqual(new byte[1], z));

            for (int i = 16; i <= 48; ++i)
            {
                BigInteger x = new BigInteger(i, random).SetBit(i - 1);
                byte[] b = x.ToByteArray();
                Assert.AreEqual((i / 8 + 1), b.Length);
                BigInteger y = new BigInteger(b);
                Assert.AreEqual(x, y);

                x = x.Negate();
                b = x.ToByteArray();
                Assert.AreEqual((i / 8 + 1), b.Length);
                y = new BigInteger(b);
                Assert.AreEqual(x, y);
            }
        }

        [Test]
        public void TestToByteArrayUnsigned()
        {
            byte[] z = BigInteger.Zero.ToByteArrayUnsigned();
            Assert.AreEqual(0, z.Length);

            for (int i = 16; i <= 48; ++i)
            {
                BigInteger x = new BigInteger(i, random).SetBit(i - 1);
                byte[] b = x.ToByteArrayUnsigned();
                Assert.AreEqual((i + 7) / 8, b.Length);
                BigInteger y = new BigInteger(1, b);
                Assert.AreEqual(x, y);

                x = x.Negate();
                b = x.ToByteArrayUnsigned();
                Assert.AreEqual(i / 8 + 1, b.Length);
                y = new BigInteger(b);
                Assert.AreEqual(x, y);
            }
        }

        [Test]
        public void TestToString()
        {
            string s = "12345667890987654321";

            Assert.AreEqual(s, new BigInteger(s).ToString());
            Assert.AreEqual(s, new BigInteger(s, 10).ToString(10));
            Assert.AreEqual(s, new BigInteger(s, 16).ToString(16));

            for (int i = 0; i < 100; ++i)
            {
                BigInteger n = new BigInteger(i, random);

                Assert.AreEqual(n, new BigInteger(n.ToString(2), 2));
                Assert.AreEqual(n, new BigInteger(n.ToString(10), 10));
                Assert.AreEqual(n, new BigInteger(n.ToString(16), 16));
            }

            // Radix version
            int[] radices = new int[] { 2, 8, 10, 16 };
            int trials = 256;

            BigInteger[] tests = new BigInteger[trials];
            for (int i = 0; i < trials; ++i)
            {
                int len = random.Next(i + 1);
                tests[i] = new BigInteger(len, random);
            }

            foreach (int radix in radices)
            {
                for (int i = 0; i < trials; ++i)
                {
                    BigInteger n1 = tests[i];
                    string str = n1.ToString(radix);
                    BigInteger n2 = new BigInteger(str, radix);
                    Assert.AreEqual(n1, n2);
                }
            }
        }

        [Test]
        public void TestValueOf()
        {
            Assert.AreEqual(-1, BigInteger.ValueOf(-1).SignValue);
            Assert.AreEqual(0, BigInteger.ValueOf(0).SignValue);
            Assert.AreEqual(1, BigInteger.ValueOf(1).SignValue);

            for (long i = -5; i < 5; ++i)
            {
                Assert.AreEqual(i, BigInteger.ValueOf(i).IntValue);
            }
        }

        [Test]
        public void TestXor()
        {
            for (int i = -10; i <= 10; ++i)
            {
                for (int j = -10; j <= 10; ++j)
                {
                    Assert.AreEqual(
                        Val(i ^ j),
                        Val(i).Xor(Val(j)),
                        "Problem: " + i + " XOR " + j + " should be " + (i ^ j));
                }
            }
        }

        private static BigInteger Val(long n) => BigInteger.ValueOf(n);

        private static BigInteger Mersenne(int e) => Two.Pow(e).Subtract(One);

        private static readonly BigInteger Zero = BigInteger.Zero;
        private static readonly BigInteger One = BigInteger.One;
        private static readonly BigInteger Two = BigInteger.Two;
        private static readonly BigInteger Three = BigInteger.Three;

        private static readonly BigInteger MinusOne = One.Negate();
        private static readonly BigInteger MinusTwo = Two.Negate();

        private static readonly int[] FirstPrimes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
        private static readonly int[] NonPrimes = { 0, 1, 4, 10, 20, 21, 22, 25, 26, 27 };

        private static readonly int[] MersennePrimeExponents = { 2, 3, 5, 7, 13, 17, 19, 31, 61, 89 };
        private static readonly int[] NonPrimeExponents = { 1, 4, 6, 9, 11, 15, 23, 29, 37, 41 };
    }
}
